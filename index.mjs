#!/usr/bin/env node
// mcp-googleplay-reviews — a reviews-only MCP server for Google Play.
//
// The capability boundary IS the trust guarantee: this server exposes ONLY
// read reviews + reply to a review (Android Publisher v3). There is deliberately
// no release, track, listing, image, in-app-product, subscription, or APK/AAB
// upload tool — adding one would widen what the service account can do, so
// don't. Scope the service account narrowly too (reply-to-reviews only).
//
// Auth: a service-account RS256 JWT is signed from the key file at
// GOOGLE_APPLICATION_CREDENTIALS and exchanged for a short-lived OAuth access
// token. The private key is never logged or copied; only the access token is
// sent, as a Bearer token to Google.
//
// Dependency-free ESM (Node 18+ global fetch, built-in crypto). Handlers are
// exported for tests; the stdio JSON-RPC loop runs only when executed directly.

import { readFileSync, realpathSync } from "node:fs";
import { sign as cryptoSign } from "node:crypto";
import { fileURLToPath } from "node:url";

const GP_BASE = "https://androidpublisher.googleapis.com/androidpublisher/v3/applications";
const SCOPE = "https://www.googleapis.com/auth/androidpublisher";
const MAX_REPLY_CHARS = 350; // Google Play hard limit on reply text

export const TOOLS = [
  {
    name: "list_reviews",
    description:
      "List recent user reviews for an app (Google Play returns reviews where the user left text, typically from the last week). Each review includes its reviewId, author, star rating, comment text, device/app-version, and the existing developer reply if one exists. Page with nextPageToken.",
    inputSchema: {
      type: "object",
      properties: {
        packageName: { type: "string", description: "App package name, e.g. 'com.example.app'" },
        maxResults: { type: "number", description: "Max reviews per page, 1–100 (default 50)" },
        translationLanguage: {
          type: "string",
          description: "Optional BCP-47 language to translate reviews into, e.g. 'en'",
        },
        startToken: {
          type: "string",
          description: "Pagination token from a previous nextPageToken",
        },
      },
      required: ["packageName"],
    },
  },
  {
    name: "reply_to_review",
    description:
      "Reply to a user review. Replies are limited to 350 characters. Replying again to the same review edits the existing reply.",
    inputSchema: {
      type: "object",
      properties: {
        packageName: { type: "string", description: "App package name, e.g. 'com.example.app'" },
        reviewId: { type: "string", description: "The reviewId from list_reviews" },
        replyText: { type: "string", description: "Reply text (max 350 characters)" },
      },
      required: ["packageName", "reviewId", "replyText"],
    },
  },
];

const b64url = (input) => Buffer.from(input).toString("base64url");

/**
 * Exchange a service-account key for a short-lived OAuth access token via the
 * RS256 JWT-bearer grant. Returns the access_token string.
 */
export async function getAccessToken({ serviceAccount, fetchImpl = fetch }) {
  const tokenUri = serviceAccount.token_uri || "https://oauth2.googleapis.com/token";
  const now = Math.floor(Date.now() / 1000);
  const header = b64url(
    JSON.stringify({ alg: "RS256", typ: "JWT", kid: serviceAccount.private_key_id }),
  );
  const claims = b64url(
    JSON.stringify({
      iss: serviceAccount.client_email,
      scope: SCOPE,
      aud: tokenUri,
      iat: now,
      exp: now + 3600,
    }),
  );
  const signingInput = `${header}.${claims}`;
  const signature = cryptoSign("RSA-SHA256", Buffer.from(signingInput), serviceAccount.private_key);
  const assertion = `${signingInput}.${b64url(signature)}`;
  const res = await fetchImpl(tokenUri, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      grant_type: "urn:ietf:params:oauth:grant-type:jwt-bearer",
      assertion,
    }).toString(),
  });
  const text = await res.text();
  const data = text ? JSON.parse(text) : {};
  if (!res.ok || !data.access_token) {
    throw new Error(data.error_description || data.error || `Token exchange failed (${res.status})`);
  }
  return data.access_token;
}

async function gp(method, path, { token, fetchImpl, body, query }) {
  const url = new URL(`${GP_BASE}${path}`);
  for (const [k, v] of Object.entries(query ?? {})) {
    if (v !== undefined && v !== null) url.searchParams.set(k, String(v));
  }
  const res = await fetchImpl(url.toString(), {
    method,
    headers: {
      Authorization: `Bearer ${token}`,
      ...(body ? { "Content-Type": "application/json" } : {}),
    },
    ...(body ? { body: JSON.stringify(body) } : {}),
  });
  const text = await res.text();
  const data = text ? JSON.parse(text) : {};
  if (!res.ok) {
    throw new Error(data?.error?.message || `Google Play API error ${res.status}`);
  }
  return data;
}

const toIso = (ts) => (ts?.seconds ? new Date(Number(ts.seconds) * 1000).toISOString() : "");

export async function callTool(name, args, { token, fetchImpl = fetch }) {
  if (!token) throw new Error("Google Play credentials are not set — the tool is not configured.");
  switch (name) {
    case "list_reviews": {
      if (!args.packageName) throw new Error("packageName is required");
      const maxResults = Math.min(Math.max(Number(args.maxResults) || 50, 1), 100);
      const data = await gp("GET", `/${encodeURIComponent(args.packageName)}/reviews`, {
        token,
        fetchImpl,
        query: {
          maxResults,
          translationLanguage: args.translationLanguage,
          token: args.startToken,
        },
      });
      const reviews = (data.reviews ?? []).map((r) => {
        const user = r.comments?.find((c) => c.userComment)?.userComment;
        const dev = r.comments?.find((c) => c.developerComment)?.developerComment;
        return {
          reviewId: r.reviewId,
          authorName: r.authorName ?? "",
          rating: user?.starRating,
          text: user?.text ?? "",
          device: user?.device ?? "",
          appVersionName: user?.appVersionName ?? "",
          lastModified: toIso(user?.lastModified),
          developerReply: dev ? { text: dev.text ?? "", lastModified: toIso(dev.lastModified) } : null,
        };
      });
      return {
        reviews,
        count: reviews.length,
        nextPageToken: data.tokenPagination?.nextPageToken ?? null,
      };
    }
    case "reply_to_review": {
      if (!args.packageName) throw new Error("packageName is required");
      if (!args.reviewId) throw new Error("reviewId is required");
      if (!args.replyText) throw new Error("replyText is required");
      if (args.replyText.length > MAX_REPLY_CHARS) {
        throw new Error(`replyText exceeds the ${MAX_REPLY_CHARS}-character Google Play limit`);
      }
      const data = await gp(
        "POST",
        `/${encodeURIComponent(args.packageName)}/reviews/${encodeURIComponent(args.reviewId)}:reply`,
        { token, fetchImpl, body: { replyText: args.replyText } },
      );
      return {
        reviewId: args.reviewId,
        replyText: data.result?.replyText ?? args.replyText,
        lastEdited: toIso(data.result?.lastEdited),
      };
    }
    default:
      throw new Error(`Unknown tool: ${name}`);
  }
}

// ─── stdio JSON-RPC transport (runs only when executed directly) ───

let cachedToken;
async function tokenFromEnv() {
  const path = process.env.GOOGLE_APPLICATION_CREDENTIALS;
  if (!path) return undefined;
  const now = Math.floor(Date.now() / 1000);
  if (cachedToken && cachedToken.exp > now + 60) return cachedToken.value;
  const serviceAccount = JSON.parse(readFileSync(path, "utf-8"));
  const value = await getAccessToken({ serviceAccount });
  cachedToken = { value, exp: now + 3300 };
  return value;
}

function send(msg) {
  process.stdout.write(JSON.stringify(msg) + "\n");
}

async function handle(req) {
  if (req.id === undefined || req.id === null) return; // notifications get no response

  const reply = (result) => send({ jsonrpc: "2.0", id: req.id, result });
  const fail = (code, message) => send({ jsonrpc: "2.0", id: req.id, error: { code, message } });

  switch (req.method) {
    case "initialize":
      return reply({
        protocolVersion: req.params?.protocolVersion || "2025-06-18",
        capabilities: { tools: {} },
        serverInfo: { name: "googleplay-reviews", version: "1.0.0" },
      });
    case "ping":
      return reply({});
    case "tools/list":
      return reply({ tools: TOOLS });
    case "tools/call": {
      const { name, arguments: args } = req.params ?? {};
      try {
        const result = await callTool(name, args ?? {}, { token: await tokenFromEnv() });
        return reply({ content: [{ type: "text", text: JSON.stringify(result, null, 2) }] });
      } catch (err) {
        return reply({
          content: [{ type: "text", text: String(err.message ?? err) }],
          isError: true,
        });
      }
    }
    default:
      return fail(-32601, `Method not found: ${req.method}`);
  }
}

function main() {
  let buffer = "";
  process.stdin.setEncoding("utf-8");
  process.stdin.on("data", (chunk) => {
    buffer += chunk;
    if (buffer.length > 1_000_000) buffer = "";
    let nl;
    while ((nl = buffer.indexOf("\n")) !== -1) {
      const line = buffer.slice(0, nl).trim();
      buffer = buffer.slice(nl + 1);
      if (!line) continue;
      let req;
      try {
        req = JSON.parse(line);
      } catch {
        continue;
      }
      handle(req).catch(() => {});
    }
  });
}

// Run only when invoked directly (realpath handles npx/bin symlinks); dormant when imported by tests.
function isMainModule() {
  if (!process.argv[1]) return false;
  try {
    return realpathSync(process.argv[1]) === realpathSync(fileURLToPath(import.meta.url));
  } catch {
    return false;
  }
}

if (isMainModule()) main();
