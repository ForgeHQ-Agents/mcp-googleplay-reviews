import { test } from "node:test";
import assert from "node:assert/strict";
import { generateKeyPairSync, createPublicKey, verify } from "node:crypto";
import { TOOLS, callTool, getAccessToken } from "../index.mjs";

/** A fetch stub that records calls and replies with `data` (status 200). */
function stubFetch(data) {
  const calls = [];
  const fetchImpl = async (url, opts) => {
    calls.push({
      url,
      method: opts?.method ?? "GET",
      body: opts?.body ? JSON.parse(opts.body) : undefined,
    });
    return { ok: true, status: 200, text: async () => JSON.stringify(data) };
  };
  return { fetchImpl, calls };
}

const token = "ya29.fake";

test("exposes exactly the two review tools", () => {
  assert.deepEqual(TOOLS.map((t) => t.name).sort(), ["list_reviews", "reply_to_review"]);
});

test("exposes NO release/track/listing/image/upload/product tool", () => {
  const names = TOOLS.map((t) => t.name.toLowerCase());
  for (const forbidden of [
    "release",
    "track",
    "listing",
    "image",
    "upload",
    "apk",
    "bundle",
    "product",
    "subscription",
    "commit",
  ]) {
    assert.ok(!names.some((n) => n.includes(forbidden)), `unexpected tool matching "${forbidden}"`);
  }
});

test("list_reviews GETs the reviews endpoint and maps user + developer comments", async () => {
  const { fetchImpl, calls } = stubFetch({
    reviews: [
      {
        reviewId: "gp:rev1",
        authorName: "Alex",
        comments: [
          {
            userComment: {
              text: "Nice app",
              starRating: 4,
              device: "Pixel",
              appVersionName: "1.2.0",
              lastModified: { seconds: "1700000000" },
            },
          },
          { developerComment: { text: "Thanks!", lastModified: { seconds: "1700001000" } } },
        ],
      },
    ],
    tokenPagination: { nextPageToken: "next123" },
  });
  const out = await callTool("list_reviews", { packageName: "com.example.app" }, { token, fetchImpl });
  assert.equal(calls[0].method, "GET");
  assert.ok(calls[0].url.includes("/com.example.app/reviews"));
  assert.equal(out.reviews[0].reviewId, "gp:rev1");
  assert.equal(out.reviews[0].rating, 4);
  assert.equal(out.reviews[0].text, "Nice app");
  assert.equal(out.reviews[0].developerReply.text, "Thanks!");
  assert.equal(out.nextPageToken, "next123");
});

test("reply_to_review POSTs replyText to the :reply endpoint", async () => {
  const { fetchImpl, calls } = stubFetch({
    result: { replyText: "Glad you like it", lastEdited: { seconds: "1700002000" } },
  });
  const out = await callTool(
    "reply_to_review",
    { packageName: "com.example.app", reviewId: "gp:rev1", replyText: "Glad you like it" },
    { token, fetchImpl },
  );
  assert.equal(calls[0].method, "POST");
  assert.ok(calls[0].url.includes("/com.example.app/reviews/gp%3Arev1:reply"));
  assert.deepEqual(calls[0].body, { replyText: "Glad you like it" });
  assert.equal(out.reviewId, "gp:rev1");
});

test("reply_to_review rejects text over the 350-char limit before calling the API", async () => {
  const { fetchImpl, calls } = stubFetch({});
  await assert.rejects(
    () =>
      callTool(
        "reply_to_review",
        { packageName: "p", reviewId: "r", replyText: "x".repeat(351) },
        { token, fetchImpl },
      ),
    /350-character/i,
  );
  assert.equal(calls.length, 0);
});

test("errors without credentials, on unknown tool, and on missing required args", async () => {
  const { fetchImpl, calls } = stubFetch({});
  await assert.rejects(() => callTool("list_reviews", { packageName: "p" }, { token: undefined }), /not configured/i);
  await assert.rejects(() => callTool("invalid_tool", {}, { token }), /unknown tool/i);
  await assert.rejects(() => callTool("list_reviews", {}, { token, fetchImpl }), /packageName is required/i);
  await assert.rejects(() => callTool("reply_to_review", { packageName: "p", reviewId: "r" }, { token, fetchImpl }), /replyText is required/i);
  assert.equal(calls.length, 0);
});

test("signs an RS256 JWT-bearer assertion that verifies, and returns the access token", async () => {
  const { privateKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
  const pem = privateKey.export({ type: "pkcs8", format: "pem" });
  const serviceAccount = {
    client_email: "svc@p.iam.gserviceaccount.com",
    private_key: pem,
    private_key_id: "pkid",
    token_uri: "https://oauth2.googleapis.com/token",
  };
  let assertion = "";
  const fetchImpl = async (_url, opts) => {
    assertion = new URLSearchParams(opts.body).get("assertion") ?? "";
    return { ok: true, status: 200, text: async () => JSON.stringify({ access_token: "ya29.real", expires_in: 3600 }) };
  };
  const tok = await getAccessToken({ serviceAccount, fetchImpl });
  assert.equal(tok, "ya29.real");
  const [h, p, s] = assertion.split(".");
  assert.equal(assertion.split(".").length, 3);
  const claims = JSON.parse(Buffer.from(p, "base64url").toString());
  assert.equal(claims.iss, "svc@p.iam.gserviceaccount.com");
  assert.ok(claims.scope.includes("androidpublisher"));
  const pub = createPublicKey(pem);
  const ok = verify("RSA-SHA256", Buffer.from(`${h}.${p}`), pub, Buffer.from(s, "base64url"));
  assert.ok(ok, "RS256 assertion should verify");
});
