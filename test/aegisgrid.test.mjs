import test from "node:test";
import assert from "node:assert/strict";
import { buildSecurityFindingPayload } from "../src/aegisgrid.mjs";

test("AegisGrid payload preserves finding evidence and creates a stable event id", () => {
  const report = {
    generatedAt: "2026-09-17T12:00:00.000Z",
    target: "https://authorized.example.com",
    risk: { score: 74, grade: "C" },
    summary: { pagesScanned: 8, requestsMade: 17 },
    findings: [{
      id: "credential-form-cross-origin",
      severity: "high",
      title: "Credential form crosses origin",
      evidence: "The form action is cross-origin.",
      location: "https://authorized.example.com/login",
      remediation: "Keep credential submission same-origin.",
      fingerprint: "a1b2c3d4e5f60718",
      confidenceScore: 0.95,
    }],
  };
  const first = buildSecurityFindingPayload(report);
  const second = buildSecurityFindingPayload(report);
  assert.equal(first.externalEventId, second.externalEventId);
  assert.equal(first.source, "sentinelscan");
  assert.equal(first.severity, "high");
  assert.equal(first.createIncident, true);
  assert.equal(first.findings[0].fingerprint, "a1b2c3d4e5f60718");
});
