# Security Policy

SentinelScan is a **defensive** tool. Its most important security property is that it stays inside the boundary the operator wrote down. This policy covers what that means, what to report, and how.

## Intended use

Use SentinelScan only against systems you **own** or have **explicit written authorization** to assess. It is for defensive testing. Stop immediately if the owner asks you to.

## What counts as a security issue in SentinelScan

Please report anything that lets the scanner go beyond its guarantees. See [docs/SAFETY.md](docs/SAFETY.md) for the full list. Examples:

| Category | Example |
| --- | --- |
| **Scope bypass** | A request, redirect, or discovered link reaches an origin or path outside the scope file |
| **Unsafe request** | Anything other than a `GET`, a form submission, or a request the docs say is never sent |
| **Budget bypass** | A scan exceeds its page, resource, request, time, or response-size limits |
| **Credential leakage** | Auth-header values or credential-shaped query values appear in a report, checkpoint, log, or a request to a non-allow-listed origin |
| **Dashboard exposure** | The local server accepts a scan without `confirmAuthorized`, ignores a budget ceiling, or allows unintended access |
| **Report injection** | Evidence from a scanned site executes or renders as active content in the HTML report |
| **Incorrect evidence** | A finding reports something the response did not contain |

## How to report

- **A guardrail bypass, credential leak, or anything exploitable:** please do **not** open a public issue. Use GitHub's **private vulnerability reporting** on this repository (the *Security* tab, then *Report a vulnerability*), or contact the maintainers privately.
- **A wrong or noisy finding, or a non-sensitive scanner bug:** open a [Bug report](../../issues/new?template=bug_report.md).

Include:

1. The SentinelScan version (`node src/cli.mjs --help` prints it) and your Node.js version
2. A **minimal local reproduction**: a fixture server or unit test is ideal
3. The scope file and flags you used, with anything sensitive removed

> [!IMPORTANT]
> Do not include secrets, personal data, or the URL of a target you are not authorized to test.

## Scope boundary of the project

SentinelScan deliberately does **not** implement exploitation, credential attacks, denial of service, SSRF probing, directory fuzzing, form submission, or authentication bypass. Contributions that add those capabilities will not be accepted into the safe default scanner.

## Handling your own scan results

Reports can contain internal URLs, response details, and inventory of your client-side APIs. Treat them as sensitive: keep them private, restrict who can read CI artifacts, and limit who can edit the `SENTINEL_SCOPE_JSON` repository secret.

## Supported versions

Security fixes are made against the latest release on the default branch.
