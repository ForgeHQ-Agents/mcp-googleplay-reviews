# mcp-googleplay-reviews

A small, **reviews-only** MCP server for Google Play, backed by the
[Android Publisher API v3](https://developers.google.com/android-publisher/api-ref/rest/v3/reviews).
It lets an agent read user reviews and reply to them — and deliberately nothing else.

## Why so narrow?

The capability boundary *is* the trust guarantee. This server exposes only the
two review tools below. There is intentionally **no** release, track, listing,
image, in-app-product, subscription, or APK/AAB upload tool, so the service
account you give it can't be used to ship a release or change your store
listing. Scope the service account itself narrowly too — grant only the
**Reply to reviews** permission in Play Console.

It is also **dependency-free** — pure Node 18+ (`fetch` + built-in `crypto`),
no third-party packages — so there is no supply chain to audit beyond this one
file (`index.mjs`).

## Tools

| Tool | Description |
| --- | --- |
| `list_reviews` | List recent user reviews for an app, including any existing developer reply. Args: `packageName`, `maxResults`, `translationLanguage`, `startToken`; returns `nextPageToken` for paging. |
| `reply_to_review` | Reply to a review (`packageName`, `reviewId`, `replyText`, max 350 chars). Replying again edits the existing reply. |

> Note: Google Play only returns reviews where the user left text, and typically
> only from the last week — this is an API limitation, not a limitation of this server.

## Authentication

Create a Google Cloud service account with a JSON key, enable the **Google Play
Android Developer API**, and in Play Console → Users and permissions invite the
service account's email with only the **Reply to reviews** permission.

| Env var | What |
| --- | --- |
| `GOOGLE_APPLICATION_CREDENTIALS` | Path to the service-account JSON key file |

The key is read only to sign a short-lived RS256 JWT, which is exchanged for an
OAuth access token scoped to `androidpublisher`; the key is never logged, copied,
or sent anywhere but Google's token endpoint.

## Run

```bash
GOOGLE_APPLICATION_CREDENTIALS=/path/to/service-account.json \
npx -y github:ForgeHQ-Agents/mcp-googleplay-reviews
```

The agent passes the app's package name (e.g. `com.example.app`) as `packageName`.

## Test

```bash
npm test   # node --test, zero dependencies
```

## License

MIT
