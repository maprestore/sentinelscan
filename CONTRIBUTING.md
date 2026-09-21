# Contributing to SentinelScan

Thank you for helping make defensive security tooling safer and more useful. SentinelScan has one rule that outranks every feature request:

> **It must stay bounded, authorized, and non-destructive.**

Read [docs/SAFETY.md](docs/SAFETY.md) first. It explains the guarantees your change must preserve.

- [What we accept, and what we decline](#what-we-accept-and-what-we-decline)
- [Getting set up](#getting-set-up)
- [Adding a detector](#adding-a-detector)
- [Adding an attack-path rule](#adding-an-attack-path-rule)
- [Documentation](#documentation)
- [Pull requests](#pull-requests)
- [Reporting bugs](#reporting-bugs)
- [Licensing](#licensing)

## What we accept, and what we decline

| ✅ Welcome | 🚫 Declined, always |
| --- | --- |
| New passive detectors with a fixture and a safety note | Brute force, credential testing, or password guessing |
| Better evidence, remediation text, and confidence tuning | Exploit payloads or authentication bypass logic |
| Fewer false positives | Denial-of-service or load-generating behavior |
| Report formats and integrations | SSRF probing or directory/parameter fuzzing |
| Docs, examples, and tests | Submitting forms, or following links outside the scope |

Also: never add secrets, real target URLs, cookies, tokens, or private response data to fixtures.

## Getting set up

SentinelScan has **no runtime dependencies** and needs Node.js 20 or newer.

```bash
git clone https://github.com/maprestore/sentinelscan.git
cd sentinelscan
npm test                       # local fixtures only; no internet required
node examples/weak-site.mjs    # a safe, local-only demo target on 127.0.0.1:4599
```

Please keep it dependency-free. A change that adds a runtime dependency needs a very strong reason.

Before you push, run the same checks CI runs:

```bash
npm test
for f in src/*.mjs; do node --check "$f"; done
```

## Adding a detector

Every detector must ship with all four of these:

1. **A local fixture or unit test.** No test may contact the public internet.
2. **A stable finding ID and remediation text.** IDs are lowercase and hyphenated, and are permanent: fingerprints, baselines, and SARIF rules depend on them.
3. **A severity rationale.** Say why it is `info`, `low`, `medium`, or `high`.
4. **A safety note.** Explain why the request behavior is safe. Most detectors add **no** requests at all, because they inspect a response the crawler already has.

### Step by step

**1. Emit the finding.** Detectors call `finding(id, severity, title, evidence, location, remediation)` in `src/scanner.mjs`. Header checks live in `addHeaderFindings()`. For example (illustrative, not shipped):

```js
if (!headerValue(headers, "cross-origin-opener-policy")) {
  findings.push(finding(
    "missing-cross-origin-opener-policy",
    "info",
    "Cross-Origin-Opener-Policy is missing",
    `The response from ${url} does not advertise Cross-Origin-Opener-Policy.`,
    url,
    "Consider Cross-Origin-Opener-Policy: same-origin once cross-window integrations are reviewed.",
  ));
}
```

**2. Set confidence if it is a candidate.** If the detector matches a *pattern* rather than a fact, add a profile so it is discounted in the risk score:

```js
// FINDING_PROFILES in src/scanner.mjs
"my-candidate-finding": { category: "client-exposure", confidence: "medium", confidenceScore: 0.7, status: "candidate" },
```

Anything without a profile defaults to `observed`, `high`, `0.9`.

**3. Write a test.** Follow `test/scanner.test.mjs`: start a local `http.createServer`, scan it, and assert on the finding IDs.

```js
const report = await scan(`http://127.0.0.1:${port}/`, {
  delayMs: 0,
  scope: { name: "fixture", allowedOrigins: [`http://127.0.0.1:${port}`] },
});
assert.ok(report.findings.some((item) => item.id === "missing-cross-origin-opener-policy"));
```

**3b. Test the negative case too.** A fixture that *should not* trigger the finding is what keeps false positives out.

**4. Document it.** Add the finding to [docs/DETECTIONS.md](docs/DETECTIONS.md) in the right group, and update the counts in the README if they change. `test/docs.test.mjs` fails if a finding ID in the source is missing from the catalog.

### Severity guide

| Severity | Use when |
| --- | --- |
| `high` | A plausible, direct path to credential or data exposure (for example a password form over HTTP) |
| `medium` | A meaningful defensive control is missing or weak |
| `low` | Hardening gaps and best-practice deviations |
| `info` | Inventory and context that a reviewer should know about, but that is not a weakness by itself |

## Adding an attack-path rule

Attack paths are declarative. Add an object to `DEFAULT_ATTACK_PATH_RULES` in `src/risk.mjs`:

```js
{
  id: "my-correlation-path",
  requiresAll: ["finding-id-one", "finding-id-two"],   // every one must be present
  severity: "medium",
  title: "A short, plain-language story",
  whyItMatters: "Why these findings are worse together than apart.",
  nextAction: "The single most useful thing to do first.",
}
```

A path only appears when **all** `requiresAll` findings are present. Add a test in `test/risk.test.mjs`, and list the rule in [docs/DETECTIONS.md](docs/DETECTIONS.md#correlated-attack-paths).

## Documentation

- Keep the tone plain, specific, and honest. Prefer "the scanner sends a single GET" over "the scanner is safe".
- Every claim should be checkable in the code. If you change behavior that a doc describes, update the doc in the same PR.
- The banner, terminal, and report images in `docs/assets/` are produced from real runs of the bundled demo site. If output formats change, regenerate them.

## Pull requests

A good PR description covers:

- **The user problem** it solves
- **The evidence produced** (paste a real finding or report excerpt from a local fixture)
- **The safety boundary**: what requests it makes (ideally none new)
- **The false-positive trade-off**

The pull request template walks you through it. CI (tests on Node 20 and 22, syntax checks, CodeQL) must pass before review.

## Reporting bugs

Use the **Bug report** issue template. Reproduce with a local fixture or a target you are authorized to assess, and never paste secrets, private URLs, customer data, or credentials. Redact tokens, cookies, personal data, and internal hostnames from evidence.

If the scanner made an unsafe request or bypassed a guardrail, see [SECURITY.md](SECURITY.md).

## Licensing

SentinelScan is released under the [MIT License](LICENSE). By submitting a contribution, you agree that it is licensed under the same terms, and that you have the right to submit it. Do not copy in code, fixtures, or text you do not have the right to relicense.

## Code of conduct

Participation is governed by our [Code of Conduct](CODE_OF_CONDUCT.md).
