# SentinelScan

SentinelScan is a small, explainable web-security posture scanner for websites you own or are explicitly authorized to assess. Version 0.3 adds application inventory, transparent risk scoring, correlated attack paths, and SARIF export.

It is intentionally bounded and non-destructive. The MVP uses `GET` requests only, stays on the target origin, limits page count and response size, and never submits forms, guesses credentials, exploits a bug, or attempts to bypass access controls.

## Quick start

Requires Node.js 20 or newer. No package install is needed.

```bash
cd sentinelscan
node src/cli.mjs \
  --target https://your-authorized-site.example \
  --scope scope.example.json \
  --confirm-authorized
```

Copy `scope.example.json` to a private file and replace the example origin. The target origin must appear exactly in `allowedOrigins`. Redirects to any other origin are blocked before the next request.

## Real dashboard scans

The GitHub Pages copy is static and only runs the safe fixture. To scan an authorized target from the dashboard, run the local server:

```bash
npm run dashboard
```

Open `http://127.0.0.1:4173`, enter the target, confirm that you own or are authorized to assess it, and run the scan. The dashboard calls the same bounded scanner as the CLI. It uses `GET` requests only, stays on the exact target origin, limits the crawl to 20 pages, and does not submit forms or attempt exploits.

The local server binds to `127.0.0.1` by default. Do not expose it publicly.

Save a machine-readable report:

```bash
node src/cli.mjs \
  --target https://your-authorized-site.example \
  --scope scope.example.json \
  --confirm-authorized \
  --format json \
  --out reports/first-scan.json
```

The output directory must already exist. Keep reports private if they contain internal URLs or response details.

## GitHub

The repository includes GitHub Actions for Node.js quality checks, CodeQL, Dependabot, and a manually triggered authorized scan that uploads SARIF findings to GitHub Code Scanning. The authorized workflow is disabled until a maintainer creates the `SENTINEL_SCOPE_JSON` repository secret. See [docs/github-actions.md](docs/github-actions.md).

Compare a later run with a prior JSON report:

```bash
node src/cli.mjs \
  --target https://your-authorized-site.example \
  --scope scope.example.json \
  --confirm-authorized \
  --format json \
  --baseline reports/first-scan.json \
  --out reports/second-scan.json
```

The comparison labels the run `regressed`, `improved`, or `unchanged` and lists new, resolved, and unchanged findings by stable fingerprint.

Send findings to code-scanning tools with SARIF:

```bash
node src/cli.mjs \
  --target https://your-authorized-site.example \
  --scope scope.example.json \
  --confirm-authorized \
  --format sarif \
  --out reports/scan.sarif
```

## Checks in version 0.3

- HTTPS posture, HTTP-to-HTTPS redirect, and HSTS presence
- Content-Security-Policy, Referrer-Policy, Permissions-Policy, MIME sniffing, and clickjacking headers
- Cookie `Secure`, `HttpOnly`, and `SameSite` attributes
- Password forms that submit over HTTP
- HTTPS pages that reference HTTP resources
- Third-party scripts without Subresource Integrity metadata
- Public Git metadata at `/.git/HEAD`
- `robots.txt` paths that appear to name administrative or private areas
- Availability of `/.well-known/security.txt`
- A bounded same-origin HTML crawl
- Exact-origin scope enforcement for initial requests and redirects
- Stable finding fingerprints and baseline regression comparison
- Inventory of pages, forms, links, scripts, and external scripts
- Transparent 0-100 risk score with an explainable grade
- Correlated attack paths that connect separate observations into reviewable risk stories
- SARIF 2.1.0 output for security and engineering workflows

Findings are leads for review, not proof of exploitability. A security professional should confirm context, business impact, and false positives before changing production systems.

## Guardrails

The CLI refuses to run unless both `--confirm-authorized` and `--scope` are supplied. This is a reminder, not a legal permission system: use the scanner only within a written scope, respect rate limits, and stop if the owner asks you to stop.

The scanner does not include brute force, credential testing, exploit payloads, denial-of-service behavior, SSRF probing, directory fuzzing, or authentication bypass logic.

## Tests

```bash
npm test
```

The tests use a local fixture server and do not contact the public internet.

## Roadmap

1. Add a signed scope file and tamper-evident audit log.
2. Add authenticated browser mapping only through a user-supplied test session, never guessed credentials.
3. Add accessibility and dependency policy checks that remain passive.
4. Add a local HTML report with evidence drill-down.
5. Add a review workflow so every new check has a fixture, a severity rationale, and an explicit safety note.
