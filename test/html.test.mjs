import test from "node:test";
import assert from "node:assert/strict";
import { toHtml } from "../src/html.mjs";

test("HTML report escapes evidence and renders execution proof", () => {
  const html = toHtml({
    target: "https://example.test",
    finishedAt: "2026-09-17T00:00:00Z",
    summary: { pagesScanned: 1, resourcesScanned: 1, requestsMade: 2, elapsedMs: 12, termination: "queue-exhausted", findings: 1, byConfidence: { high: 1 } },
    risk: { score: 22, grade: "C" },
    findings: [{ id: "demo", severity: "low", title: "Unsafe <tag>", evidence: "<script>alert(1)</script>", location: "https://example.test/", remediation: "Fix it", fingerprint: "abc", confidence: "high", category: "demo", status: "observed" }],
    attackPaths: [],
    inventory: { totals: { forms: 0, passwordForms: 0, scripts: 1, clientApiEndpoints: [] } },
    requests: [{ status: 200, elapsedMs: 4, bytesRead: 10, url: "https://example.test/" }],
  });
  assert.match(html, /Evidence, not noise/);
  assert.match(html, /&lt;script&gt;alert\(1\)&lt;\/script&gt;/);
  assert.doesNotMatch(html, /<script>alert\(1\)/);
  assert.match(html, /Request evidence/);
});
