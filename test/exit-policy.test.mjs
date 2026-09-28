import test from "node:test";
import assert from "node:assert/strict";
import { evaluateExitPolicy, normalizeExitPolicy } from "../src/exit-policy.mjs";

const report = {
  findings: [
    { id: "high", fingerprint: "1", severity: "high", location: "https://example.test/" },
    { id: "low", fingerprint: "2", severity: "low", location: "https://example.test/" },
    { id: "suppressed", fingerprint: "3", severity: "high", location: "https://example.test/", triage: { state: "suppressed" } },
  ],
};

test("severity policy ignores suppressed findings and reports matched evidence", () => {
  const result = evaluateExitPolicy(report, { failOnSeverity: "high" });
  assert.equal(result.failed, true);
  assert.deepEqual(result.matchedFindings.map((item) => item.id), ["high"]);
});

test("baseline policies distinguish new, changed, and regression conditions", () => {
  const current = { ...report, comparison: { summary: { status: "improved", new: 0, changed: 1, resolved: 0 } } };
  assert.equal(evaluateExitPolicy(current, { failOnBaseline: "new" }).failed, false);
  assert.equal(evaluateExitPolicy(current, { failOnBaseline: "changed" }).failed, true);
  assert.equal(evaluateExitPolicy(current, { failOnBaseline: "regressed" }).failed, false);
  assert.equal(evaluateExitPolicy({ ...report, comparison: { summary: { status: "regressed", new: 1, changed: 0, resolved: 0 } } }, { failOnBaseline: "regressed" }).failed, true);
});

test("required baseline fails when no baseline was supplied", () => {
  const result = evaluateExitPolicy({ findings: [] }, { requireBaseline: true });
  assert.equal(result.failed, true);
  assert.match(result.reasons[0], /baseline is required/i);
});

test("exit policy values are strictly normalized", () => {
  assert.deepEqual(normalizeExitPolicy(), { failOnSeverity: null, failOnBaseline: "never", requireBaseline: false });
  assert.throws(() => normalizeExitPolicy({ failOnSeverity: "critical" }), /failOnSeverity/);
  assert.throws(() => normalizeExitPolicy({ failOnBaseline: "all" }), /failOnBaseline/);
});
