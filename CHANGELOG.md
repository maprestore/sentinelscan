# Changelog

All notable changes to SentinelScan are documented here. The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- `LICENSE`: SentinelScan is released under the MIT License, and `package.json` now declares `"license": "MIT"`.
- `examples/weak-site.mjs` and `examples/weak-site.scope.json`: a deliberately weak demo site bound to `127.0.0.1` so anyone can try the scanner with no target.
- `test/example.test.mjs`: keeps the demo site and the README's sample results in sync.
- `test/pacing.test.mjs`, new cases in `test/baseline.test.mjs` and `test/server.test.mjs`: cover the fixes below.
- `test/docs.test.mjs`: fails when a finding ID is missing from `docs/DETECTIONS.md` or a relative documentation link is broken.
- Documentation: `docs/SAFETY.md`, `docs/ARCHITECTURE.md`, `docs/CLI.md`, `docs/API.md`, `docs/DETECTIONS.md`, and a documentation index.
- Repository health files: `CODE_OF_CONDUCT.md`, this changelog, a pull request template, and issue template configuration.
- README visuals: an animated banner, an animated terminal recording of real output, and a report screenshot, plus a social preview image (`docs/assets/social-preview.png`).

### Changed

- Rewrote `README.md`, `CONTRIBUTING.md`, `SECURITY.md`, and `docs/github-actions.md` for clarity and completeness.
- The request delay (`--delay-ms`, `delayMs`) now applies to **every** request, including redirect hops and the nine well-known path checks. Previously it applied only between crawled pages, so the well-known checks ran back to back. With the default of 250 ms, scans that reach those checks are correspondingly slower.
- `POST /api/scan` now answers unexpected server faults with `500` instead of `400`.

### Fixed

- **A single request timeout no longer aborts the whole scan.** A request that exceeded `timeoutMs` used to throw and end the scan (and mark a dashboard job `canceled`). It is now recorded as a `request-failed` finding ("The request timed out after N ms.") and the scan continues. Only an operator cancellation stops a scan.
- **Baseline comparison no longer merges findings that share a fingerprint.** Several instances of one issue on the same URL (for example two cookies missing `HttpOnly`) were collapsed into one, hiding regressions and fixes. They are now matched individually, by identical evidence first and then by count.
- **The dashboard API returns `4xx` for invalid input.** `POST /api/scans` returned `500` for a missing confirmation, an out-of-scope target, malformed JSON, or an invalid auth header. It now returns `400`, and `413` for a body over 16 KB.
- **The wall-clock budget is enforced during the well-known path checks**, so the paced checks cannot overrun `maxElapsedMs`.
- Cancellation now interrupts the wait between requests instead of waiting it out.

## [0.5.0]

> This entry summarizes the capabilities of the current release. Earlier history was not recorded in this changelog.

### Capabilities

- **Safety:** GET-only requests, mandatory scope file and `--confirm-authorized`, scope enforced on every URL and redirect hop, hard execution budgets, credential redaction, and operator-only auth headers limited to allow-listed origins.
- **Scanning:** bounded HTML, JavaScript, and JSON crawl; client API endpoint inventory; 48 finding types across transport, browser policy, cookies, authentication forms, client exposure, disclosure, and infrastructure.
- **Intelligence:** confidence-aware findings with stable fingerprints, transparent risk scoring with diminishing returns, and five declarative attack-path rules.
- **Outputs:** text, JSON, standalone HTML, and SARIF 2.1.0.
- **Workflow:** baseline regression comparison, atomic resumable checkpoints, a localhost dashboard with an asynchronous jobs API (progress and cancellation), and opt-in passive infrastructure checks (DNS, TLS, SPF, DMARC, DKIM, CAA, Certificate Transparency).
- **CI:** Node.js 20 and 22 quality checks, CodeQL, Dependabot, and a manually triggered authorized scan that uploads SARIF to GitHub Code Scanning.
