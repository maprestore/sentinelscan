# CLI Reference

```bash
node src/cli.mjs --target <url> --scope <file> --confirm-authorized [options]
```

Run `node src/cli.mjs --help` for the built-in summary.

- [Required flags](#required-flags)
- [Output](#output)
- [Budgets](#budgets)
- [Authenticated observation](#authenticated-observation)
- [Infrastructure checks](#infrastructure-checks)
- [Checkpoints and baselines](#checkpoints-and-baselines)
- [Config file](#config-file)
- [Scope file](#scope-file)
- [Exit codes](#exit-codes)
- [Recipes](#recipes)

## Required flags

| Flag | Description |
| --- | --- |
| `--target <url>` | One `http://` or `https://` target URL. Embedded credentials and credential-shaped query parameters are rejected. |
| `--scope <path>` | JSON [scope file](#scope-file) listing the origins that may be contacted. The target itself must be inside it. |
| `--confirm-authorized` | Your acknowledgement that you own the target or hold written authorization. **No request is sent without it.** |

## Output

| Flag | Description |
| --- | --- |
| `--format <text\|json\|sarif\|html>` | Report format. Default `text`. |
| `--out <path>` | **Also** write the report to a file. The report is still printed to stdout, so redirect (`> /dev/null`, or `> NUL` on Windows) if you only want the file. |

| Format | Use it for |
| --- | --- |
| `text` | Reading in a terminal |
| `json` | Automation, baselines, dashboards |
| `html` | A private, shareable, standalone review report |
| `sarif` | GitHub Code Scanning (SARIF 2.1.0) |

## Budgets

Every run is bounded by independent limits. Exhausting any of them stops the scan cleanly and records the reason in `summary.termination`.

| Flag | Default | Description |
| --- | ---: | --- |
| `--max-pages <n>` | 20 | HTML pages to visit |
| `--max-resources <n>` | 40 | JS/JSON resources to inspect |
| `--max-requests <n>` | 80 | Hard cap across pages, resources, redirects, and metadata requests |
| `--max-elapsed-ms <n>` | 120000 | Wall-clock cap for one scan |
| `--max-response-bytes <n>` | 1000000 | Maximum bytes read from a single response |
| `--timeout-ms <n>` | 8000 | Per-request timeout |
| `--delay-ms <n>` | 250 | Minimum pause between **any** two requests: crawl, redirect hops, and the well-known path checks (`0` disables it) |

All values must be integers: positive for limits, non-negative for the delay. The redirect limit (5 hops) can be changed only through `maxRedirects` in a [config file](#config-file).

## Authenticated observation

| Flag | Description |
| --- | --- |
| `--auth-headers <path>` | JSON object of request headers for an **operator-supplied test session** |
| `--auth-header-origins <a,b>` | Comma-separated exact origins allowed to receive those headers. Default: the target origin |

```json
{ "authorization": "Bearer replace-with-a-short-lived-test-token" }
```

Wildcard scopes never implicitly receive credentials. Header values are never written to reports or checkpoints.

## Infrastructure checks

Opt-in passive DNS, TLS, and email-policy metadata.

| Flag | Description |
| --- | --- |
| `--infrastructure` | Enable DNS, TLS, SPF, DMARC, DKIM (common selectors), and CAA checks |
| `--email-domain <domain>` | Domain for email-policy lookups. Defaults to the target hostname |
| `--certificate-transparency` | Also query Certificate Transparency. Implies `--infrastructure` |

> [!WARNING]
> `--certificate-transparency` sends the target hostname to the public **crt.sh** service. `--email-domain` is not limited by your origin scope. See [Safety](SAFETY.md#third-party-and-non-http-lookups).

## Checkpoints and baselines

| Flag | Description |
| --- | --- |
| `--checkpoint <path>` | Write progress atomically so an interrupted scan can resume |
| `--resume <path>` | Resume from a checkpoint. Refuses a different target or scope |
| `--baseline <path>` | Compare this run with a previous **JSON** report |

A baseline comparison adds a `comparison` object to the report:

| Field | Meaning |
| --- | --- |
| `summary.new` / `resolved` / `unchanged` / `changed` | Counts of findings by change type (matched by fingerprint) |
| `summary.riskDelta` | Current score minus baseline score |
| `summary.status` | `regressed` (new findings, or a severity increase), `improved`, or `unchanged` |
| `newFindings`, `resolvedFindings`, `unchangedFindings`, `changedFindings` | The findings themselves |

> [!NOTE]
> A fingerprint identifies an issue on a URL path, so several instances can share one (for example two cookies that both lack `HttpOnly` on the same page). Those instances are compared **individually**: matched first by identical evidence, then by count. A third such cookie is reported as **new**, and fixing one of two is reported as **resolved**.

## Config file

`--config <path>` loads scan defaults from JSON. Command-line flags override it.

```json
{
  "maxPages": 20,
  "maxResources": 40,
  "maxRequests": 80,
  "maxElapsedMs": 120000,
  "maxResponseBytes": 1000000,
  "timeoutMs": 8000,
  "delayMs": 250,
  "maxRedirects": 5,
  "checkInfrastructure": false,
  "certificateTransparency": false,
  "emailDomain": "",
  "dkimSelectors": ["default", "google", "selector1", "selector2", "k1"]
}
```

See [`config.example.json`](../config.example.json).

## Scope file

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

| Field | Rules |
| --- | --- |
| `allowedOrigins` | **Required**, at least one. Clean `http(s)` origins only (no path, query, or credentials). A single leading `*.` wildcard is allowed and matches subdomains but **not** the bare domain |
| `includePaths` | Optional. If set, only these paths (and their children) are allowed. Entries must start with `/`. A trailing `/*` matches everything below |
| `excludePaths` | Optional. These paths are always blocked, and take precedence over `includePaths` |
| `notes` | Free text for humans |

Ports and schemes must match exactly: `https://example.com` does not allow `https://example.com:8443` or `http://example.com`.

## Exit codes

| Code | Meaning |
| ---: | --- |
| `0` | The scan (or `--help`) completed. **This includes runs that found problems** |
| `1` | SentinelScan itself failed: bad arguments, a missing `--scope` or `--confirm-authorized`, an out-of-scope target, an unreadable file |

Findings do not change the exit code because they are review leads, not test failures. To gate a pipeline, use `--baseline` and inspect `comparison.summary.status`, or upload SARIF and use code-scanning rules.

## Recipes

**A quick, polite look at a production site**
```bash
node src/cli.mjs --target https://your-authorized-site.example --scope scope.local.json \
  --confirm-authorized --max-pages 5 --delay-ms 1000
```

**A shareable report**
```bash
node src/cli.mjs --target https://your-authorized-site.example --scope scope.local.json \
  --confirm-authorized --format html --out reports/scan.html > /dev/null
```

**Fail a CI job on regressions**
```bash
node src/cli.mjs --target https://your-authorized-site.example --scope scope.local.json \
  --confirm-authorized --format json --baseline reports/main.json --out reports/pr.json > /dev/null
node -e 'const r=require("./reports/pr.json"); process.exit(r.comparison.summary.status==="regressed"?1:0)'
```

**A long scan you can interrupt**
```bash
node src/cli.mjs ... --checkpoint reports/scan.ckpt.json     # Ctrl+C any time
node src/cli.mjs ... --resume reports/scan.ckpt.json          # continues where it stopped
```
