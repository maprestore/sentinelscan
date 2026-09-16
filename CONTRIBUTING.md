# Contributing to SentinelScan

## Before opening a change

- Keep requests bounded, authorized, and non-destructive.
- Do not add brute force, credential attacks, exploit payloads, denial-of-service behavior, SSRF probing, directory fuzzing, or authentication bypass logic.
- Do not add secrets, real target URLs, cookies, tokens, or private response data to fixtures.

## Development

SentinelScan has no runtime dependencies and requires Node.js 20 or newer.

```bash
npm test
```

Every new detector should include:

1. A local fixture or unit test.
2. A stable finding identifier and remediation text.
3. A severity rationale.
4. A note explaining why the request behavior is safe.

## Pull requests

Explain the user problem, the evidence produced, the safety boundary, and any false-positive tradeoff. The GitHub Actions checks must pass before review.
