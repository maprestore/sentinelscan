import test from "node:test";
import assert from "node:assert/strict";
import { compareReports } from "../src/baseline.mjs";

const item = (fingerprint, id) => ({ fingerprint, id, severity: "low" });

test("compareReports identifies regressions and resolved findings", () => {
  const baseline = {
    target: "https://example.test",
    finishedAt: "2026-09-15T00:00:00.000Z",
    findings: [item("same", "missing-referrer-policy"), item("fixed", "missing-hsts")],
  };
  const current = {
    target: "https://example.test",
    findings: [item("same", "missing-referrer-policy"), item("new", "missing-permissions-policy")],
  };

  const result = compareReports(current, baseline);
  assert.equal(result.summary.status, "regressed");
  assert.equal(result.summary.new, 1);
  assert.equal(result.summary.resolved, 1);
  assert.equal(result.summary.unchanged, 1);
  assert.equal(result.newFindings[0].id, "missing-permissions-policy");
  assert.equal(result.resolvedFindings[0].id, "missing-hsts");
});

test("baseline comparison reports severity and risk deltas", () => {
  const baseline = { target: "https://example.test", findings: [item("same", "finding")], risk: { score: 20 } };
  const current = { target: "https://example.test", findings: [{ ...item("same", "finding"), severity: "high" }], risk: { score: 55 } };
  const result = compareReports(current, baseline);
  assert.equal(result.summary.changed, 1);
  assert.equal(result.summary.riskDelta, 35);
  assert.equal(result.summary.status, "regressed");
});
