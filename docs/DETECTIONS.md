# Detection Catalog

Every finding SentinelScan can emit, generated from the source of `src/scanner.mjs` and `src/infrastructure.mjs`.

**48 finding types**: 9 high, 7 medium, 23 low, 9 informational.
Findings are review leads, not proof of exploitability.

> [!NOTE]
> **Status** tells you how much to trust a result. `observed` means the scanner directly saw the condition (for example, a missing header). `candidate` means it is a pattern that needs a human decision (for example, a value that *looks* like a secret). Candidates carry a lower confidence score and are discounted in the risk score.

- [How findings are scored](#how-findings-are-scored)
- [Correlated attack paths](#correlated-attack-paths)


## Transport and TLS

How traffic reaches the browser.

| Finding ID | Severity | What was observed | Recommended fix | Status |
| --- | --- | --- | --- | --- |
| `site-served-over-http` | 🔴 high | Site is served over HTTP | Deploy HTTPS and redirect every HTTP request to the HTTPS origin. | `observed` · high (0.90) |
| `http-redirects-to-https` | 🔵 info | HTTP redirects to HTTPS | Keep the redirect and consider HSTS after confirming all subdomains are HTTPS-ready. | `observed` · high (0.90) |
| `missing-hsts` | 🟡 low | Strict transport security is missing | After confirming all relevant subdomains support HTTPS, add a carefully staged HSTS policy. | `observed` · high (0.90) |
| `weak-hsts-duration` | 🟡 low | Strict transport security duration is short | Use a staged rollout, then target at least six months of HSTS coverage once every required hostname supports HTTPS. | `observed` · high (0.90) |
| `hsts-missing-subdomains` | 🔵 info | Strict transport security does not cover subdomains | Add includeSubDomains only after confirming every relevant subdomain is HTTPS-ready. | `observed` · high (0.90) |
| `mixed-content-reference` | 🟠 medium | HTTPS page references HTTP content | Serve every page resource over HTTPS or remove the dependency. | `observed` · high (0.90) |
| `tls-certificate-invalid` | 🔴 high | TLS certificate is not trusted by Node | Install a complete certificate chain from a trusted issuer and verify hostname coverage. | `observed` · high (0.98) |
| `tls-connection-failed` | 🟠 medium | TLS connection could not be inspected | Confirm that the public HTTPS service is available and presents a certificate for the requested host. | `observed` · high (0.90) |

## Browser policy and caching

Headers and markup that decide what the browser will trust.

| Finding ID | Severity | What was observed | Recommended fix | Status |
| --- | --- | --- | --- | --- |
| `missing-content-security-policy` | 🟡 low | Missing Content-Security-Policy | Set a policy appropriate for the application and verify it does not break required functionality. | `observed` · high (0.90) |
| `weak-content-security-policy` | 🟠 medium | Content-Security-Policy contains weak directives | Remove unsafe-inline, unsafe-eval, and broad wildcards where possible; use nonces or hashes for intentional inline code. | `observed` · high (0.90) |
| `incomplete-content-security-policy` | 🟡 low | Content-Security-Policy does not define a default or script policy | Define an explicit default-src and script-src policy appropriate for the application. | `observed` · high (0.90) |
| `missing-referrer-policy` | 🟡 low | Missing Referrer-Policy | Set a policy appropriate for the application and verify it does not break required functionality. | `observed` · high (0.90) |
| `missing-permissions-policy` | 🟡 low | Missing Permissions-Policy | Set a policy appropriate for the application and verify it does not break required functionality. | `observed` · high (0.90) |
| `missing-x-content-type-options` | 🟡 low | MIME sniffing protection is missing | Send X-Content-Type-Options: nosniff for browser-served resources. | `observed` · high (0.90) |
| `missing-clickjacking-protection` | 🟠 medium | Clickjacking protection is missing | Set a deliberate frame policy, such as frame-ancestors 'none' or a trusted embedding origin. | `observed` · high (0.90) |
| `obsolete-frame-policy` | 🟡 low | X-Frame-Options uses an obsolete directive | Use CSP frame-ancestors for a modern, testable framing policy. | `observed` · high (0.90) |
| `sensitive-page-cache-policy` | 🟡 low | Sensitive-looking page lacks a restrictive cache policy | Set a deliberate cache policy for authenticated or sensitive pages and verify intermediary behavior. | `candidate` · medium (0.75) |
| `cors-wildcard-with-credentials` | 🔴 high | CORS allows credentials with a wildcard origin | Allow only explicit trusted origins and review whether credentialed cross-origin access is required. | `observed` · high (0.90) |
| `cross-origin-iframe-without-sandbox` | 🟡 low | Cross-origin iframe has no sandbox attribute | Add the narrowest sandbox policy compatible with the integration and explicitly review postMessage trust. | `observed` · high (0.95) |
| `external-window-missing-noopener` | 🟡 low | New window link lacks rel=noopener | Add rel=noopener, and add noreferrer only when the referrer behavior is intentionally changed. | `observed` · high (0.90) |
| `external-script-without-sri` | 🟡 low | External script has no integrity attribute | Pin the script to a trusted version and add an integrity hash with an appropriate crossorigin value. | `observed` · high (0.90) |

## Cookies

Session cookie attributes on observed responses.

| Finding ID | Severity | What was observed | Recommended fix | Status |
| --- | --- | --- | --- | --- |
| `cookie-missing-secure` | 🟡 low | Cookie is missing Secure | Add Secure to cookies that should only travel over HTTPS. | `observed` · high (0.90) |
| `cookie-missing-httponly` | 🟡 low | Cookie is missing HttpOnly | Add HttpOnly to cookies that do not need JavaScript access. | `observed` · high (0.90) |
| `cookie-missing-samesite` | 🟡 low | Cookie is missing SameSite | Set SameSite=Lax or SameSite=Strict unless a cross-site use case is intentional. | `observed` · high (0.90) |

## Authentication forms

Forms that contain a password field. Nothing is ever submitted.

| Finding ID | Severity | What was observed | Recommended fix | Status |
| --- | --- | --- | --- | --- |
| `credential-form-over-http` | 🔴 high | Credential form submits over HTTP | Submit credentials only to an HTTPS endpoint and redirect HTTP traffic before the form is shown. | `observed` · high (0.90) |
| `credential-form-cross-origin` | 🔴 high | Credential form submits to another origin | Confirm the destination is an explicitly trusted authentication boundary and that its scope, transport, cookies, and CSRF protections are reviewed together. | `observed` · high (0.95) |
| `credential-form-uses-get` | 🔴 high | Credential form uses GET | Use POST over HTTPS for credential submission and confirm credentials are not accepted in query strings. | `observed` · high (0.99) |

## Client-side exposure

What the page ships to every visitor.

| Finding ID | Severity | What was observed | Recommended fix | Status |
| --- | --- | --- | --- | --- |
| `potential-client-secret` | 🔴 high | Potential secret-like value is visible to clients | Treat the value as exposed: revoke or rotate it, then move privileged operations behind a server-side authorization boundary. | `candidate` · medium (0.72) |
| `client-dangerous-sink` | 🟡 low | Client code contains a security-sensitive sink | Review data flow into the sink, prefer safe DOM APIs, and validate postMessage origins explicitly. | `candidate` · low (0.50) |
| `public-source-map-reference` | 🟡 low | Client code references a source map | Publish source maps only when their exposure is intentional and ensure they contain no secrets or internal source that should remain private. | `observed` · high (0.96) |
| `sensitive-data-in-json` | 🟠 medium | JSON response contains sensitive-looking fields | Confirm the response is intentionally public and remove credentials, session material, and unnecessary personal data from client-visible JSON. | `candidate` · medium (0.78) |
| `potential-open-redirect` | 🟡 low | Redirect-like parameter accepts an absolute URL | Validate redirect destinations against an explicit allowlist and reject untrusted absolute URLs. | `candidate` · low (0.45) |
| `client-api-endpoint` | 🔵 info | Client-side API endpoint was inventoried | Review the endpoint's authentication, authorization, rate limits, and data minimization separately. | `observed` · high (0.98) |

## Files and disclosure

Findings from nine fixed well-known paths (each fetched once with a single GET) and from response headers.

| Finding ID | Severity | What was observed | Recommended fix | Status |
| --- | --- | --- | --- | --- |
| `exposed-git-metadata` | 🔴 high | Git metadata is publicly readable | Remove repository metadata from the web root and rotate any credentials that may have been committed. | `observed` · high (0.90) |
| `exposed-environment-file` | 🔴 high | Environment file is publicly readable | Remove environment files from the web root, rotate any values they contained, and block the path at the server or CDN. | `observed` · high (0.90) |
| `public-configuration-or-api-description` | 🟠 medium | Public configuration or API description is readable | Confirm the document is intentionally public, remove secrets and internal endpoints, and protect operational configuration. | `observed` · high (0.90) |
| `robots-discloses-sensitive-path` | 🔵 info | robots.txt names sensitive-looking paths | Treat robots.txt as public. Do not rely on it to protect administrative or private paths. | `observed` · high (0.90) |
| `technology-disclosure` | 🔵 info | Server technology is disclosed | Remove or generalize unnecessary version and framework identifiers where practical. | `observed` · high (0.90) |
| `security-contact-published` | 🔵 info | Security contact is published | Keep the contact and policy links current. | `observed` · high (0.90) |
| `security-contact-missing` | 🟡 low | security.txt has no Contact field | Add a monitored security contact address or URL so researchers can report issues responsibly. | `observed` · high (0.90) |
| `security-contact-expiry-invalid` | 🟡 low | security.txt has no valid Expires field | Publish a future RFC 9116 Expires timestamp and renew it before it lapses. | `observed` · high (0.90) |
| `security-contact-expired` | 🟡 low | security.txt has expired | Renew the security.txt document with a future Expires timestamp. | `observed` · high (0.90) |

## Infrastructure (opt-in)

Passive DNS, email-policy and Certificate Transparency metadata. Enabled with `--infrastructure`.

| Finding ID | Severity | What was observed | Recommended fix | Status |
| --- | --- | --- | --- | --- |
| `dns-resolution-failed` | 🟠 medium | DNS resolution failed | Verify that the target hostname has a stable public DNS record. | `observed` · high (0.90) |
| `missing-spf` | 🟡 low | SPF record was not observed | Publish an SPF policy if this domain sends email, and keep it within provider lookup limits. | `observed` · high (0.90) |
| `missing-dmarc` | 🟡 low | DMARC record was not observed | Publish a monitored DMARC policy for the domain's email-sending identity. | `observed` · high (0.90) |
| `missing-caa` | 🔵 info | CAA record was not observed | Consider restricting certificate issuance with a CAA policy when operationally appropriate. | `observed` · high (0.90) |
| `ct-no-certificates` | 🔵 info | No Certificate Transparency entries were returned | Confirm the hostname and review your certificate inventory through the issuing CA if this is unexpected. | `observed` · high (0.90) |

## Operational

| Finding ID | Severity | What was observed | Recommended fix | Status |
| --- | --- | --- | --- | --- |
| `request-failed` | 🔵 info | Request could not be completed | Verify the target is available and repeat the scan with an appropriate timeout. | `observed` · high (0.98) |

## How findings are scored

Each finding gets a stable fingerprint (`sha256` of `id|origin+path`, first 16 hex characters), so the same issue is recognised across scans and baselines (it is also included in SARIF results).

| Severity | Base points |
| --- | ---: |
| info | 0 |
| low | 6 |
| medium | 18 |
| high | 35 |

For every finding: `points = base × repeat multiplier × confidence`.

- **Repeat multiplier**: the first occurrence of an ID counts fully; the *n*th repeat counts `1/(n+1)`. Fifty pages missing the same header do not bury a real problem.
- **Confidence**: candidates use their confidence score (for example `0.72` for a possible client secret); everything else defaults to `0.90` unless the profile says otherwise.
- **Attack-path bonus**: each correlated attack path adds points (6 for the current rules).
- The total is capped at 100. Grades: `A` = 0, `B` > 0, `C` ≥ 20, `D` ≥ 40, `F` ≥ 70.

The report includes the full breakdown (`risk.factors` and per-finding `risk.contributions`) so the number can always be explained.

## Correlated attack paths

Attack paths are declarative rules in `src/risk.mjs`. A path appears only when **all** of its required findings are present, and it links their fingerprints so a reviewer can jump from the story to the evidence.

| Attack path | Severity | Requires |
| --- | --- | --- |
| `credential-interception-path` | 🔴 high | `site-served-over-http` + `credential-form-over-http` |
| `source-control-exposure-path` | 🔴 high | `exposed-git-metadata` |
| `client-secret-exposure-path` | 🔴 high | `potential-client-secret` + `client-api-endpoint` |
| `browser-supply-chain-path` | 🟠 medium | `external-script-without-sri` + `missing-content-security-policy` |
| `session-ui-defense-path` | 🟠 medium | `missing-clickjacking-protection` + `cookie-missing-samesite` |

Adding a rule is a data change, not a code change. See [CONTRIBUTING.md](../CONTRIBUTING.md#adding-an-attack-path-rule).
