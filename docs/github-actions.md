# GitHub Actions

SentinelScan is designed to run safely on GitHub without placing a target URL, scope, or credentials in source control.

## What runs automatically

- `Quality` runs the local test suite and syntax checks on Node.js 20 and 22 for pushes and pull requests.
- `CodeQL` performs a read-only JavaScript analysis.
- `Dependabot` checks GitHub Action versions monthly.

These workflows do not contact a website.

## Optional authorized scan

The `Authorized SentinelScan` workflow is manual by design. It only runs when an operator chooses **Run workflow** and supplies a target.

Before using it:

1. Open the repository's **Settings**, then **Secrets and variables**, then **Actions**.
2. Add a repository secret named `SENTINEL_SCOPE_JSON`.
3. Set its value to JSON such as:

```json
{
  "name": "authorized-production-scope",
  "allowedOrigins": ["https://your-authorized-site.example"]
}
```

The workflow refuses an empty scope secret, and SentinelScan blocks the request if the input target is not an exact allowed origin. Redirects outside the scope are blocked as well.

The workflow uploads SARIF findings to GitHub Code Scanning. Keep the scope secret restricted to trusted repository maintainers and use a written authorization record for every target.
