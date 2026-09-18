# SentinelScan

> **Authorized web security posture intelligence without destructive testing.**

[Open the live demo](https://maprestore.github.io/sentinelscan/) | Node.js 20+ | SentinelScan 0.5.1

SentinelScan is a bounded, explainable scanner for websites you own or are explicitly authorized to assess. It maps observable security posture, inventories client-facing technology, correlates related signals, and produces evidence that engineers can review and remediate.

It is deliberately not an exploit framework. SentinelScan uses safe `GET` requests, enforces an explicit scope, applies hard execution budgets, and never submits forms, guesses credentials, brute-forces, or bypasses access controls.

## Product Overview

SentinelScan connects four activities that are often separated across different tools:

- **Surface mapping**: bounded HTML, JavaScript, JSON, and API endpoint inventory.
- **Posture analysis**: transport, browser policy, cookie, cache, CORS, configuration, and infrastructure checks.
- **Risk intelligence**: confidence-aware scoring, diminishing returns, and declarative attack paths.
- **Evidence delivery**: JSON, SARIF, standalone HTML, checkpoints, baselines, and request timelines.

The live demo is a static, safe fixture. Real scans run locally through the guarded dashboard server or CLI.

## Architecture

```mermaid
flowchart LR
    A[Authorized target] --> B[Scope gate]
    B --> C[Bounded GET engine]
    C --> D[HTML pages]
    C --> E[JS and JSON resources]
    C --> F[Optional DNS TLS email CT metadata]
    D --> G[Detections and inventory]
    E --> G
    F --> G
    G --> H[Confidence-aware findings]
    H --> I[Risk and attack paths]
    I --> J[JSON / SARIF / HTML / dashboard]
```

## Scan Lifecycle

```mermaid
sequenceDiagram
    participant O as Operator
    participant S as SentinelScan
    participant T as Authorized target
    participant R as Report

    O->>S: Confirm authorization and provide scope
    S->>S: Validate target, origin, paths, headers, and budgets
    loop Until queue or hard budget is reached
        S->>T: GET one in-scope URL
        T-->>S: Response, headers, body, redirect
        S->>S: Record timing, status, bytes, inventory, and detections
    end
    S->>R: Correlate findings and calculate risk
    R-->>O: Reviewable evidence and next actions
```

## Safety Boundary

```mermaid
flowchart TB
    subgraph Allowed[Allowed behavior]
        A[GET requests]
        B[Explicit origins and paths]
        C[Bounded pages resources requests time]
        D[Passive headers body and DNS observations]
    end
    subgraph Excluded[Explicitly excluded]
        E[Form submission]
        F[Credential testing or brute force]
        G[Exploit payloads or bypass attempts]
        H[Directory fuzzing or SSRF probing]
    end
    A --> C
    B --> C
    C --> D
```

## Quick Start

Requires Node.js 20 or newer. There are no runtime dependencies to install.

```bash
cd sentinelscan
node src/cli.mjs \
  --target https://your-authorized-site.example \
  --scope scope.example.json \
  --confirm-authorized
```

The CLI requires both `--scope` and `--confirm-authorized` before it sends a request.

## Scope Configuration

Copy `scope.example.json` to a private local file and replace the example values.

```json
{
  "name": "authorized-production-scope",
  "allowedOrigins": [
    "https://your-authorized-site.example",
    "https://*.assets.your-authorized-site.example"
  ],
  "includePaths": ["/", "/app"],
  "excludePaths": ["/logout"],
  "notes": ["Written authorization recorded by the service owner."]
}
```

Scope supports exact origins, multiple origins, and a leading-subdomain wildcard. `includePaths` and `excludePaths` apply inside those origins. Redirects and discovered links outside the scope are blocked before the next request.

## Local Dashboard

The GitHub Pages demo is static. To run a real scan through the visual dashboard:

```bash
npm run dashboard
```

Open [http://127.0.0.1:4173](http://127.0.0.1:4173). The server binds to localhost by default. Do not expose it publicly.

For a private hosted deployment, set `SENTINELSCAN_API_TOKEN` to a long random value and place the server behind HTTPS:

```bash
SENTINELSCAN_API_TOKEN="replace-with-a-long-random-token" npm run dashboard
```

The health endpoint remains public for platform checks. Scan creation, progress, reports, and cancellation require `Authorization: Bearer <token>`. The local default has no token requirement.

Dashboard requests default to the exact target origin. Use the CLI when the written scope contains additional origins, path rules, authenticated headers, or infrastructure checks.

## CLI Outputs

### JSON report

```bash
node src/cli.mjs \
  --target https://your-authorized-site.example \
  --scope scope.example.json \
  --confirm-authorized \
  --format json \
  --out reports/scan.json
```

### Human review report

```bash
node src/cli.mjs \
  --target https://your-authorized-site.example \
  --scope scope.example.json \
  --confirm-authorized \
  --format html \
  --out reports/scan.html
```

The standalone HTML report includes risk, confidence, findings, attack paths, inventory, and request evidence. Keep reports private when they contain internal URLs or response details.

### SARIF for code scanning

```bash
node src/cli.mjs \
  --target https://your-authorized-site.example \
  --scope scope.example.json \
  --confirm-authorized \
  --format sarif \
  --out reports/scan.sarif
```

### Baseline regression comparison

```bash
node src/cli.mjs \
  --target https://your-authorized-site.example \
  --scope scope.example.json \
  --confirm-authorized \
  --format json \
  --baseline reports/scan.json \
  --out reports/scan-next.json
```

Comparisons report new, resolved, unchanged, and severity-changed findings, plus the risk-score delta.

## Execution Controls

Every run is bounded by independent limits:

| Control | Default | Purpose |
| --- | ---: | --- |
| HTML pages | 20 | Limits navigation surface |
| JS/JSON resources | 40 | Limits client-resource inspection |
| Total requests | 80 | Caps pages, resources, redirects, and metadata checks |
| Wall-clock time | 120 seconds | Stops unexpectedly slow runs |
| Response body | 1 MB | Prevents oversized response reads |
| Per-request timeout | 8 seconds | Bounds individual network waits |
| Redirect hops | 5 | Prevents redirect loops |

Override the main execution controls with `--max-pages`, `--max-resources`, `--max-requests`, `--max-elapsed-ms`, `--max-response-bytes`, `--timeout-ms`, and `--delay-ms`.

## Authenticated Observation

Session headers are supported only for an operator-provided, authorized test session:

```json
{
  "authorization": "Bearer replace-with-a-short-lived-test-token"
}
```

```bash
node src/cli.mjs \
  --target https://your-authorized-site.example \
  --scope scope.example.json \
  --auth-headers auth-headers.json \
  --auth-header-origins https://your-authorized-site.example \
  --confirm-authorized
```

Headers are sent only to the target origin by default. Wildcard scopes never implicitly receive credentials. Header values are not written to reports or checkpoints, and credential-shaped query parameters are rejected or redacted.

## Resumable Scans and Jobs

Write an atomic checkpoint during a CLI scan:

```bash
node src/cli.mjs \
  --target https://your-authorized-site.example \
  --scope scope.example.json \
  --checkpoint reports/scan.checkpoint.json \
  --confirm-authorized
```

Resume after interruption:

```bash
node src/cli.mjs \
  --target https://your-authorized-site.example \
  --scope scope.example.json \
  --resume reports/scan.checkpoint.json \
  --confirm-authorized
```

Long-running clients can use the local asynchronous API:

| Method | Endpoint | Purpose |
| --- | --- | --- |
| `POST` | `/api/scans` | Start a bounded scan and receive a job ID |
| `GET` | `/api/scans/:id` | Read progress or the completed report |
| `DELETE` | `/api/scans/:id` | Request cancellation |
| `POST` | `/api/scan` | Run a compatible synchronous scan |
| `GET` | `/api/health` | Read server version and capabilities |

When `SENTINELSCAN_API_TOKEN` is configured, add `Authorization: Bearer <token>` to every endpoint above except `/api/health`. This token protects the API only; it is not a replacement for user accounts, durable job storage, rate limiting, or tenant isolation in a multi-user SaaS deployment.

### AegisGrid Publishing

A completed report can be sent to a tenant's AegisGrid security intake. Keep the
API key in an environment variable, not in a committed config file:

```bash
AEGISGRID_URL=https://aegisgrid.example.com \
AEGISGRID_TENANT=your-tenant \
AEGISGRID_API_KEY=ak_... \
node src/cli.mjs \
  --target https://your-authorized-site.example \
  --scope scope.example.json \
  --confirm-authorized \
  --format json \
  --out reports/scan.json \
  --aegisgrid-url https://aegisgrid.example.com \
  --aegisgrid-tenant your-tenant
```

The connector sends risk metadata and bounded finding evidence. It never sends
session headers or raw response bodies. A report with findings requests an
AegisGrid incident; retries use a stable event ID and are deduplicated there.

## Passive Infrastructure Checks

Infrastructure checks are opt-in:

```bash
node src/cli.mjs \
  --target https://your-authorized-site.example \
  --scope scope.example.json \
  --infrastructure \
  --certificate-transparency \
  --email-domain example.com \
  --confirm-authorized
```

They inspect DNS resolution, TLS certificate status, SPF, DMARC, common DKIM selectors, CAA, and optionally Certificate Transparency. They do not send email, modify DNS, or probe certificate authorities.

## Detection Coverage

- HTTPS posture, HTTP-to-HTTPS redirect, HSTS presence, duration, and subdomain coverage.
- Content-Security-Policy quality, Referrer-Policy, Permissions-Policy, MIME sniffing, framing, CORS, and cache policy.
- Cookie `Secure`, `HttpOnly`, and `SameSite` attributes.
- Credential forms that submit over HTTP, submit cross-origin, or use GET.
- Mixed content, third-party scripts without SRI, cross-origin iframes without sandbox, and new-window links without noopener.
- Client API endpoint inventory from HTML and JavaScript.
- JSON sensitive-field inventory, source-map references, client-secret patterns, and dangerous client sinks.
- Candidate open redirects from redirect-like parameters.
- Safe checks for public Git metadata, `.env`, configuration, API descriptions, actuator endpoints, and robots disclosures.
- RFC 9116 `security.txt` Contact and Expires quality.
- Optional DNS, TLS, SPF, DMARC, DKIM, CAA, and Certificate Transparency metadata.

## Evidence and Risk

Every finding includes a stable fingerprint, evidence, location, remediation, category, confidence, status, and observation timestamp. Risk scoring is transparent and uses diminishing returns for repeated observations so crawl depth does not overwhelm prioritization.

Declarative attack-path rules connect related findings into reviewable stories, such as:

- Unencrypted transport plus an HTTP credential form.
- Missing browser defenses plus weak cookie policy.
- External scripts without SRI plus missing CSP.
- Client-visible secret-like values plus client API endpoints.

Findings are review leads, not proof of exploitability. Confirm business impact and false positives before changing production systems.

## GitHub Actions

Included workflows provide:

- Node.js quality checks on Node 20 and 22.
- CodeQL analysis.
- Dependabot updates.
- A manually triggered authorized scan that uploads SARIF to GitHub Code Scanning.

The authorized workflow requires a repository secret named `SENTINEL_SCOPE_JSON`. See [docs/github-actions.md](docs/github-actions.md).

## Project Layout

```text
src/scanner.mjs          bounded crawl, detections, checkpoints, report assembly
src/scope.mjs            exact, wildcard, multi-origin, and path enforcement
src/risk.mjs             confidence-aware scoring and attack-path rules
src/infrastructure.mjs   optional DNS, TLS, email, and CT metadata checks
src/server.mjs           localhost dashboard and asynchronous scan jobs
src/cli.mjs              command-line interface and output formats
src/html.mjs             standalone human-review report renderer
src/sarif.mjs            SARIF 2.1.0 export
test/                    local fixture and regression tests
docs/index.html          static dashboard and safe demo
```

## Development

Run the test suite:

```bash
npm test
```

The tests use local fixture servers and do not contact the public internet.

Run syntax checks:

```bash
node --check src/scanner.mjs
node --check src/server.mjs
node --check src/cli.mjs
node --check src/html.mjs
```

## Guardrails

Use SentinelScan only inside a written authorization scope. Stop if the owner asks you to stop. SentinelScan intentionally excludes brute force, credential testing, exploit payloads, denial-of-service behavior, SSRF probing, directory fuzzing, authentication bypass logic, and form submission.

## Roadmap

1. Signed scope manifests and a tamper-evident audit log.
2. Authenticated browser mapping through a user-supplied test session.
3. Passive accessibility and dependency policy checks.
4. Deeper report drill-down for request timelines and confidence.
5. A review workflow requiring a fixture, severity rationale, and safety note for every new check.
