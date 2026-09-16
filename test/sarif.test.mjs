import test from "node:test";
import assert from "node:assert/strict";
import { toSarif } from "../src/sarif.mjs";

test("SARIF export preserves finding identity and severity", () => {
  const sarif = toSarif({
    target: "https://example.test",
    scanner: { name: "SentinelScan", version: "0.3.0" },
    findings: [{
      id: "missing-hsts",
      title: "Strict transport security is missing",
      severity: "low",
      evidence: "No HSTS header.",
      remediation: "Add HSTS.",
      fingerprint: "abc123",
      location: "https://example.test/",
    }],
  });
  assert.equal(sarif.version, "2.1.0");
  assert.equal(sarif.runs[0].results[0].level, "note");
  assert.equal(sarif.runs[0].results[0].fingerprints.sentinelscan, "abc123");
});
