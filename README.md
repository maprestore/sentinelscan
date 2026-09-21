<div align="center">

<img src="docs/assets/banner.svg" alt="SentinelScan: Hunt signals. Not people." width="100%">

<br>

### A web security posture scanner with a conscience.
**Scope-locked. GET-only. Budgeted. It explains every score it gives you.**

<br>

[![Quality](https://github.com/maprestore/sentinelscan/actions/workflows/quality.yml/badge.svg)](https://github.com/maprestore/sentinelscan/actions/workflows/quality.yml)
[![CodeQL](https://github.com/maprestore/sentinelscan/actions/workflows/codeql.yml/badge.svg)](https://github.com/maprestore/sentinelscan/actions/workflows/codeql.yml)
![Node.js](https://img.shields.io/badge/node-%E2%89%A5%2020-b9ff4c?style=flat-square&logo=node.js&logoColor=white&labelColor=0b1416)
![Runtime dependencies](https://img.shields.io/badge/runtime%20dependencies-0-44e6f2?style=flat-square&labelColor=0b1416)
![Requests](https://img.shields.io/badge/requests-GET%20only-ff4fd8?style=flat-square&labelColor=0b1416)
![Version](https://img.shields.io/badge/version-0.5.0-ffbd5a?style=flat-square&labelColor=0b1416)
[![License: MIT](https://img.shields.io/badge/license-MIT-b9ff4c?style=flat-square&labelColor=0b1416)](LICENSE)

[**🛰️ Live demo**](https://maprestore.github.io/sentinelscan/) &nbsp;·&nbsp; [**⚡ Quick start**](#-quick-start-in-60-seconds) &nbsp;·&nbsp; [**🧠 How it works**](#-how-it-works) &nbsp;·&nbsp; [**🔎 Detections**](docs/DETECTIONS.md) &nbsp;·&nbsp; [**📚 Docs**](docs/README.md)

<br>

| **48** | **5** | **4** | **0** | **22** |
| :---: | :---: | :---: | :---: | :---: |
| finding types | attack-path rules | report formats | runtime dependencies | offline tests |

</div>

<br>

## 🎬 See it work

<div align="center">
<img src="docs/assets/terminal.svg" alt="Animated terminal showing a SentinelScan run: 19 findings, risk 100 out of 100, four correlated attack paths" width="900">
<br>
<sub>Real output from a scan of the bundled, local-only demo site. Try it yourself in under a minute, no target required.</sub>
</div>

<br>

SentinelScan maps the observable security posture of a website you own or are **explicitly authorized** to assess. It inventories what the browser can see, correlates related signals into reviewable stories, and hands engineers **evidence with a fix attached**, not a wall of alerts.

It is deliberately **not** an exploit framework. It never submits a form, guesses a credential, fuzzes a directory, or bypasses an access control.

## 🔥 Why SentinelScan?

| | Exploit-style scanners | **SentinelScan** |
| --- | --- | --- |
| **Requests** | Whatever finds a bug: `POST`, payloads, fuzzing | **`GET` only.** No form is ever submitted |
| **Scope** | A URL and good intentions | **A written scope file is mandatory.** Every request *and every redirect hop* is checked first |
| **Blast radius** | Crawl until done | **Hard budgets:** 80 requests, 120 s, 1 MB per response, 5 redirects (all adjustable) |
| **Results** | Hundreds of unranked alerts | **Confidence-aware findings**, diminishing returns on repeats, and correlated attack paths |
| **Explainability** | "Risk: High" | **A score you can audit,** down to the points each finding contributed |
| **Footprint** | A heavyweight stack | **`node src/cli.mjs`.** Zero runtime dependencies, about 1,900 lines of readable source |

## ⚡ Quick start in 60 seconds

> [!TIP]
> Requires **Node.js 20+**. Nothing to install: there are no runtime dependencies.

### Option A: try it safely, right now (no target needed)

The repo ships a deliberately weak demo site that binds to `127.0.0.1` only.

```bash
git clone https://github.com/maprestore/sentinelscan.git && cd sentinelscan

# terminal 1: start the local demo site
node examples/weak-site.mjs

# terminal 2: scan it
node src/cli.mjs \
  --target http://127.0.0.1:4599/ \
  --scope examples/weak-site.scope.json \
  --confirm-authorized \
  --delay-ms 0
```

You should see **19 findings, a risk of 100/100 (F), and 4 correlated attack paths**. Want the shareable version?

```bash
node src/cli.mjs --target http://127.0.0.1:4599/ --scope examples/weak-site.scope.json \
  --confirm-authorized --delay-ms 0 --format html --out demo-report.html > /dev/null
```

Open `demo-report.html` in a browser. (`--out` also prints to the terminal, so the redirect keeps it quiet; use `> NUL` on Windows.)

### Option B: scan something you own

```bash
cp scope.example.json scope.local.json      # git-ignored; list every origin you are authorized to test

node src/cli.mjs \
  --target https://your-authorized-site.example \
  --scope scope.local.json \
  --confirm-authorized
```

The CLI refuses to send a single request without **both** `--scope` and `--confirm-authorized`.

## 🧩 What you get

| | | |
| --- | --- | --- |
| **🧭 Scope gate**<br>Exact origins, multiple origins, and leading-subdomain wildcards, plus include/exclude paths. | **🛰️ Bounded GET engine**<br>Crawls HTML, JS, and JSON inside independent page, resource, request, and time budgets. | **🔎 48 finding types**<br>Transport, browser policy, cookies, auth forms, client exposure, disclosure, and infrastructure. |
| **🧠 Confidence-aware risk**<br>Candidates are discounted; repeats have diminishing returns; nothing is a black box. | **🔗 Attack paths**<br>Declarative rules turn separate findings into a story a reviewer can act on. | **📦 Four formats**<br>Text, JSON, standalone HTML, and SARIF 2.1.0 for GitHub Code Scanning. |
| **♻️ Baselines**<br>Compare runs: new, resolved, unchanged, severity-changed, and risk delta. | **⏸️ Resumable**<br>Atomic checkpoints let an interrupted scan pick up where it stopped. | **🖥️ Local dashboard**<br>Async jobs with live progress and cancel, bound to localhost. |

## 🧠 How it works

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

### Findings carry their own evidence

Every finding has a stable fingerprint, evidence, location, remediation, category, confidence, status, and timestamp. This is a real one from the demo scan:

```json
{
  "id": "credential-form-over-http",
  "severity": "high",
  "title": "Credential form submits over HTTP",
  "evidence": "A form containing a password field submits to an HTTP URL.",
  "location": "http://127.0.0.1:4599/",
  "remediation": "Submit credentials only to an HTTPS endpoint and redirect HTTP traffic before the form is shown.",
  "fingerprint": "25f3b6e7690829d9",
  "confidence": "high",
  "confidenceScore": 0.9,
  "status": "observed"
}
```

### Attack paths connect the dots

Two "high" findings are more useful as **one story**. When every required finding is present, SentinelScan links them:

> **🔴 Credentials can travel through an unencrypted path**<br>
> *Why it matters:* The site is served over HTTP and a password form submits over HTTP.<br>
> *Next action:* Move the entire sign-in flow to HTTPS, redirect HTTP before rendering the form, and then confirm the session cookie policy.

Five rules ship today (credential interception, source-control exposure, client-secret exposure, browser supply chain, session UI defense). See [the catalog](docs/DETECTIONS.md#correlated-attack-paths).

### A risk score you can audit

Every finding scores `severity × repeat-multiplier × confidence`, so fifty pages missing the same header can't bury one real problem.

| Severity | info | low | medium | high |
| --- | :---: | :---: | :---: | :---: |
| **Base points** | 0 | 6 | 18 | 35 |

The total is capped at 100 and graded `A` through `F`. The report includes the full breakdown:

```json
"factors": { "rawFindingScore": 218, "findingScore": 193.95, "confidenceDiscount": 24.05, "attackPathBonus": 24 }
```

<details>
<summary><b>Scan lifecycle (sequence diagram)</b></summary>

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

</details>

## 🛡️ The safety model

Safety is not a setting. It is the shape of the program.

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

| Lock | What it does |
| --- | --- |
| 🔐 **Authorization gate** | No request is sent without `--scope` **and** `--confirm-authorized` (`confirmAuthorized: true` in the API). |
| 🧭 **Scope allow-list** | Every URL is checked *before* it is fetched, and again on **every redirect hop**. Out-of-scope links are never queued. |
| 🪶 **GET only, redirects by hand** | Redirects are followed manually (max 5) so each hop passes the scope gate. |
| ⏱️ **Hard budgets** | Pages, resources, total requests, wall-clock time, response bytes, and per-request timeout are independent limits. |
| 🕵️ **Credential hygiene** | Auth headers go only to origins you name, and never appear in reports or checkpoints. Credential-shaped query parameters are rejected or redacted. |
| 🏠 **Localhost dashboard** | Binds to `127.0.0.1` by default, runs one job at a time, and caps request bodies at 16 KB. |

Read the full model in [docs/SAFETY.md](docs/SAFETY.md).

> [!IMPORTANT]
> Only scan systems you own or have **written authorization** to assess. Stop immediately if the owner asks you to.

## 📦 Outputs

<div align="center">
<img src="docs/assets/report-preview.png" alt="SentinelScan standalone HTML report: 'Evidence, not noise.' with risk score, request counts, and correlated attack paths" width="860">
<br>
<sub>The standalone HTML report, generated from the local demo site.</sub>
</div>

<br>

| Format | Flag | Best for |
| --- | --- | --- |
| **Text** | *(default)* | Reading in a terminal |
| **HTML** | `--format html` | A private, shareable review report. Evidence is HTML-escaped |
| **JSON** | `--format json` | Automation, baselines, dashboards |
| **SARIF 2.1.0** | `--format sarif` | GitHub Code Scanning |

Add `--out reports/scan.json` to also write the report to disk. Keep reports private: they can contain internal URLs and response details.

## 🔁 Fits your workflow

<table>
<tr>
<td width="50%" valign="top">

**♻️ Catch regressions with baselines**
```bash
node src/cli.mjs \
  --target https://your-authorized-site.example \
  --scope scope.local.json --confirm-authorized \
  --format json \
  --baseline reports/scan.json \
  --out reports/scan-next.json
```
Reports **new**, **resolved**, **unchanged**, and **severity-changed** findings, plus the risk delta.

</td>
<td width="50%" valign="top">

**⏸️ Resume interrupted scans**
```bash
# write progress as you go
node src/cli.mjs ... --checkpoint reports/scan.ckpt.json

# ...and pick up after an interruption
node src/cli.mjs ... --resume reports/scan.ckpt.json
```
Checkpoints are written atomically and refuse to resume against a different target or scope.

</td>
</tr>
<tr>
<td valign="top">

**🖥️ Local dashboard and jobs API**
```bash
npm run dashboard   # http://127.0.0.1:4173
```
`POST /api/scans` starts a job, `GET /api/scans/:id` reports progress, `DELETE` cancels. See [docs/API.md](docs/API.md).

</td>
<td valign="top">

**🚦 GitHub Actions and Code Scanning**

A manual, secret-scoped workflow runs a bounded scan and uploads SARIF, so findings land in your **Security** tab. Quality and CodeQL run on pushes and pull requests. See [docs/github-actions.md](docs/github-actions.md).

</td>
</tr>
</table>

<details>
<summary><b>🔐 Authenticated observation (operator-supplied test session)</b></summary>

<br>

Session headers are supported only for an authorized test session you provide:

```json
{ "authorization": "Bearer replace-with-a-short-lived-test-token" }
```

```bash
node src/cli.mjs \
  --target https://your-authorized-site.example \
  --scope scope.local.json \
  --auth-headers auth-headers.json \
  --auth-header-origins https://your-authorized-site.example \
  --confirm-authorized
```

Headers are sent only to the origins you list (default: the target origin). Wildcard scopes never implicitly receive credentials. Header values are not written to reports or checkpoints.

</details>

<details>
<summary><b>🌐 Passive infrastructure checks (opt-in)</b></summary>

<br>

```bash
node src/cli.mjs \
  --target https://your-authorized-site.example \
  --scope scope.local.json \
  --infrastructure --certificate-transparency --email-domain example.com \
  --confirm-authorized
```

Inspects DNS resolution, TLS certificate status, SPF, DMARC, common DKIM selectors, CAA, and optionally Certificate Transparency. Nothing is sent to your mail servers, no DNS is modified, and no certificate authority is probed.

> [!NOTE]
> `--certificate-transparency` looks up the target hostname on the public **crt.sh** service, which is a third-party request. Leave it off unless that is inside your assessment scope.

</details>

## ⚙️ Execution controls

Every run is bounded by independent limits:

| Control | Default | Flag |
| --- | ---: | --- |
| HTML pages | 20 | `--max-pages` |
| JS/JSON resources | 40 | `--max-resources` |
| Total requests | 80 | `--max-requests` |
| Wall-clock time | 120 s | `--max-elapsed-ms` |
| Response body | 1 MB | `--max-response-bytes` |
| Per-request timeout | 8 s | `--timeout-ms` |
| Pause between requests | 250 ms | `--delay-ms` |
| Redirect hops | 5 | `maxRedirects` in `--config` |

Every flag is documented in [docs/CLI.md](docs/CLI.md).

## 🔎 Detection coverage

<details>
<summary><b>48 finding types across 8 areas</b> (expand)</summary>

<br>

| Area | Examples |
| --- | --- |
| **Transport and TLS** | HTTP-only sites, missing or weak HSTS, mixed content, untrusted certificates |
| **Browser policy** | CSP quality, Referrer-Policy, Permissions-Policy, MIME sniffing, clickjacking, CORS wildcard with credentials, iframes without sandbox, scripts without SRI |
| **Cookies** | Missing `Secure`, `HttpOnly`, `SameSite` |
| **Authentication forms** | Password forms that submit over HTTP, cross-origin, or via GET |
| **Client-side exposure** | Client API inventory, secret-like values, dangerous sinks, source maps, sensitive JSON fields, candidate open redirects |
| **Files and disclosure** | Public `.git`, `.env`, config and API descriptions, `robots.txt` hints, server banners, `security.txt` quality (RFC 9116) |
| **Infrastructure** *(opt-in)* | DNS, TLS, SPF, DMARC, DKIM, CAA, Certificate Transparency |
| **Operational** | Requests that could not complete |

**[Browse the full catalog with severities and fixes →](docs/DETECTIONS.md)**

</details>

> [!NOTE]
> Findings are **review leads, not proof of exploitability.** Confirm business impact and rule out false positives before changing production systems.

## 🗂️ Project layout

```text
src/
├── scanner.mjs          bounded crawl, detections, checkpoints, report assembly
├── scope.mjs            exact, wildcard, multi-origin, and path enforcement
├── risk.mjs             confidence-aware scoring and attack-path rules
├── infrastructure.mjs   optional DNS, TLS, email, and CT metadata checks
├── server.mjs           localhost dashboard and asynchronous scan jobs
├── cli.mjs              command-line interface and output formats
├── html.mjs             standalone human-review report renderer
├── sarif.mjs            SARIF 2.1.0 export
├── baseline.mjs         report-to-report regression comparison
└── scope-file.mjs       scope file loader
examples/                local-only demo site for safe experimentation
test/                    fixture-based regression tests (no internet needed)
docs/                    documentation, static demo, and assets
```

## ❓ FAQ

<details>
<summary><b>Is it safe to run against production?</b></summary>

<br>

It is designed to be: bounded `GET` requests, a strict scope, and a default 250 ms pause between **every** request (crawl, redirect hops, and the well-known path checks). Still, run it only where you have authorization, start with the default budgets, and follow the service owner's rules of engagement.

</details>

<details>
<summary><b>Why does it exit 0 when it finds problems?</b></summary>

<br>

The CLI exits non-zero only when the scan itself fails (bad arguments, out-of-scope target, and so on). Findings are review leads, so they do not fail a run. To gate a pipeline, use `--baseline` and read `comparison.summary.status` (`regressed`, `improved`, or `unchanged`) from the JSON report, or use SARIF with GitHub code scanning rules.

</details>

<details>
<summary><b>Does it send my data anywhere?</b></summary>

<br>

Requests go to the target you scope, nothing else. The one exception is the opt-in `--certificate-transparency` flag, which queries the public crt.sh service for the target hostname. The dashboard and tests run locally.

</details>

<details>
<summary><b>Can it scan behind a login?</b></summary>

<br>

Yes, with a short-lived test session **you** provide as request headers. SentinelScan never logs in for you, never submits forms, and never tries credentials.

</details>

<details>
<summary><b>Why zero dependencies?</b></summary>

<br>

A security tool should be easy to audit. The whole scanner is plain Node.js (`fetch`, `node:test`, and friends) in about 1,900 lines. There is no dependency tree to review, and nothing to install.

</details>

## 🧪 Development

```bash
npm test          # 22 fixture-based tests; no internet required
```

The tests use local fixture servers and never contact the public internet. To add a detector, see [CONTRIBUTING.md](CONTRIBUTING.md).

## 🗺️ Roadmap

- [ ] Signed scope manifests and a tamper-evident audit log
- [ ] Authenticated browser mapping through a user-supplied test session
- [ ] Passive accessibility and dependency policy checks
- [ ] Deeper report drill-down for request timelines and confidence
- [ ] A review workflow requiring a fixture, severity rationale, and safety note for every new check

## 🤝 Community

- **Contribute:** [CONTRIBUTING.md](CONTRIBUTING.md). Every new check needs a fixture, a severity rationale, and a safety note.
- **Report a scanner problem:** [SECURITY.md](SECURITY.md)
- **Be kind:** [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md)
- **What changed:** [CHANGELOG.md](CHANGELOG.md)

## 📄 License

SentinelScan is open source under the [MIT License](LICENSE). You are free to use, modify, and distribute it.

> [!NOTE]
> The license permits broad use, so it cannot itself require authorization. That requirement is the project's **policy for responsible use**, and it is built into the tool: no request is sent without a scope and `--confirm-authorized`. See the [safety model](docs/SAFETY.md).

<br>

<div align="center">

**Use SentinelScan only inside a written authorization scope.**<br>
<sub>It intentionally excludes brute force, credential testing, exploit payloads, denial-of-service behavior, SSRF probing, directory fuzzing, authentication bypass logic, and form submission.</sub>

<br>

<sub>🛰️ **SentinelScan** · hunt signals, not people</sub>

</div>
