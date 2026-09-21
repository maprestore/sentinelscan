# Dashboard API

The local dashboard (`npm run dashboard`) exposes a small JSON API for driving scans from your own tooling. It uses the same scanner, the same scope gate, and the same guardrails as the CLI.

> [!WARNING]
> The server binds to `127.0.0.1` by default (override with `HOST` and `PORT`). It has **no authentication**. Do not expose it to a network you do not fully trust.

- [Endpoints](#endpoints)
- [Start a scan](#start-a-scan)
- [Poll for progress](#poll-for-progress)
- [Cancel a scan](#cancel-a-scan)
- [Request body](#request-body)
- [Limits and errors](#limits-and-errors)
- [Example client](#example-client)

## Endpoints

| Method | Endpoint | Purpose |
| --- | --- | --- |
| `GET` | `/api/health` | Server version and capabilities |
| `POST` | `/api/scans` | Start a bounded scan and receive a job ID (`202`) |
| `GET` | `/api/scans/:id` | Read progress, or the completed report |
| `DELETE` | `/api/scans/:id` | Request cancellation (`202`) |
| `POST` | `/api/scan` | Run a compatible **synchronous** scan and wait for the report |
| `GET` | `/` | The dashboard UI |

Prefer the asynchronous `/api/scans` flow for anything that can take more than a few seconds.

## Start a scan

```bash
curl -s -X POST http://127.0.0.1:4173/api/scans \
  -H 'content-type: application/json' \
  -d '{"target":"http://127.0.0.1:4599/","confirmAuthorized":true,"delayMs":0}'
```

```json
{
  "id": "c4ce2337-f83b-48f0-8889-fa17316462ca",
  "status": "queued",
  "location": "/api/scans/c4ce2337-f83b-48f0-8889-fa17316462ca"
}
```

`confirmAuthorized` **must** be `true`. If you omit `scope`, it defaults to the exact target origin.

## Poll for progress

```bash
curl -s http://127.0.0.1:4173/api/scans/c4ce2337-f83b-48f0-8889-fa17316462ca
```

```json
{
  "id": "c4ce2337-f83b-48f0-8889-fa17316462ca",
  "status": "complete",
  "createdAt": "2026-09-21T03:27:09.096Z",
  "startedAt": "2026-09-21T03:27:09.097Z",
  "finishedAt": "2026-09-21T03:27:09.228Z",
  "progress": {
    "phase": "metadata-completed",
    "target": "http://127.0.0.1:4599/",
    "pagesScanned": 2,
    "resourcesScanned": 1,
    "requestsMade": 12,
    "elapsedMs": 113
  },
  "error": null,
  "report": { "...": "full report, present when status is complete" }
}
```

| `status` | Meaning |
| --- | --- |
| `queued` | Accepted, about to start |
| `running` | In progress. `progress` updates as requests complete |
| `complete` | Finished. `report` holds the full [report](ARCHITECTURE.md#the-report) |
| `canceled` | Stopped by `DELETE` |
| `error` | Failed. `error` holds the reason |

`progress.phase` is one of `queued`, `started`, `request-started`, `request-completed`, `request-failed`, or `metadata-completed`.

Jobs are kept in memory for **15 minutes** after they finish, then discarded.

## Cancel a scan

```bash
curl -s -X DELETE http://127.0.0.1:4173/api/scans/<id>
```

Cancellation is cooperative: the running request is aborted and no further requests are sent.

## Request body

| Field | Type | Default | Notes |
| --- | --- | --- | --- |
| `target` | string | required | `http(s)` URL |
| `confirmAuthorized` | boolean | required | Must be exactly `true` |
| `scope` | object | target origin | Same shape as a [scope file](CLI.md#scope-file). The target must be inside it |
| `maxPages` | number | 20 | Clamped to 1 to 50 |
| `maxResources` | number | 40 | Clamped to 1 to 100 |
| `maxRequests` | number | 80 | Clamped to 1 to 200 |
| `maxElapsedMs` | number | 120000 | Clamped to 1,000 to 600,000 |
| `delayMs` | number | 250 | Clamped to 0 to 2,000 |
| `timeoutMs` | number | 8000 | Clamped to 1,000 to 8,000 |
| `checkInfrastructure` | boolean | `false` | Opt-in DNS/TLS/email checks |
| `certificateTransparency` | boolean | `false` | Opt-in. Queries crt.sh |
| `emailDomain` | string | target hostname | For email-policy lookups |
| `authHeaders` | object | none | Operator-supplied test-session headers |
| `authHeaderOrigins` | string[] | `[target origin]` | Exact origins that may receive `authHeaders` |

Out-of-range numbers are clamped, not rejected. The request body itself is limited to 16 KB.

## Limits and errors

- **One scan at a time.** Starting a second while one is queued or running returns `409`.
- Errors are JSON: `{ "error": "..." }`.

| Status | When | Example `error` |
| ---: | --- | --- |
| `400` | The request is invalid. Missing `confirmAuthorized`, an out-of-scope target, a bad scheme, forbidden auth headers, or a body that is not a JSON object | `Refusing to scan without explicit authorization confirmation.` |
| `404` | Unknown or expired job, or unknown route | `Scan job not found or expired.` |
| `409` | A scan is already queued or running | `A scan is already running in this local dashboard.` |
| `413` | The request body is over 16 KB | `Request body is too large.` |
| `500` | An unexpected server fault | |

`POST /api/scans` validates the request **before** queueing a job, so an invalid request fails immediately with a `4xx` instead of producing a failed job. The synchronous `POST /api/scan` uses the same validation and the same status codes.

## Example client

```js
const base = "http://127.0.0.1:4173";

const start = await fetch(`${base}/api/scans`, {
  method: "POST",
  headers: { "content-type": "application/json" },
  body: JSON.stringify({ target: "http://127.0.0.1:4599/", confirmAuthorized: true, delayMs: 0 }),
});
const { location } = await start.json();

let job;
do {
  await new Promise((resolve) => setTimeout(resolve, 500));
  job = await (await fetch(`${base}${location}`)).json();
  console.log(job.status, job.progress.requestsMade);
} while (job.status === "queued" || job.status === "running");

if (job.status === "complete") {
  console.log(`Risk ${job.report.risk.score}/100 (${job.report.risk.grade}), ${job.report.findings.length} findings`);
}
```

## Health

```bash
curl -s http://127.0.0.1:4173/api/health
```

```json
{
  "realScan": true,
  "mode": "bounded-passive",
  "targetRequests": "GET only",
  "version": "0.5.0",
  "activeJobs": 0,
  "capabilities": [
    "multi-origin scopes",
    "client API inventory",
    "resumable CLI scans",
    "progress and cancellation",
    "optional DNS/TLS/email/CT metadata"
  ]
}
```
