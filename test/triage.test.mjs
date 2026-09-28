import test from "node:test";
import assert from "node:assert/strict";
import { applyTriage, normalizeSuppressions, triageCounts } from "../src/triage.mjs";
import { compareReports } from "../src/baseline.mjs";

const finding = (fingerprint) => ({ id: "demo", fingerprint, severity: "high", evidence: fingerprint, location: "https://example.test/" });

test("active suppressions retain findings but remove them from actionable counts", () => {
  const suppressions = normalizeSuppressions([{ fingerprint: "a", reason: "Accepted until the migration is complete.", owner: "platform", expiresAt: "2099-01-01T00:00:00Z" }]);
  const findings = applyTriage([finding("a"), finding("b")], suppressions, Date.parse("2026-01-01T00:00:00Z"));
  assert.equal(findings[0].triage.state, "suppressed");
  assert.equal(findings[1].triage.state, "open");
  assert.deepEqual(triageCounts(findings), { actionableFindings: 1, suppressedFindings: 1 });
});

test("expired suppressions are visible and do not suppress findings", () => {
  const suppressions = normalizeSuppressions([{ fingerprint: "a", reason: "Temporary exception.", expiresAt: "2020-01-01T00:00:00Z" }]);
  const [result] = applyTriage([finding("a")], suppressions, Date.parse("2026-01-01T00:00:00Z"));
  assert.equal(result.triage.state, "open");
  assert.equal(result.triage.suppressionExpired, true);
});

test("suppressed current findings are not reported as resolved", () => {
  const baseline = { target: "https://example.test", scope: { allowedOrigins: ["https://example.test"] }, findings: [finding("a")] };
  const current = { target: baseline.target, scope: baseline.scope, findings: [{ ...finding("a"), triage: { state: "suppressed", reason: "Accepted", expiresAt: "2099-01-01T00:00:00.000Z" } }] };
  const comparison = compareReports(current, baseline);
  assert.equal(comparison.summary.resolved, 0);
  assert.equal(comparison.summary.suppressed, 1);
  assert.equal(comparison.suppressedInsteadOfResolved.length, 1);
});

test("suppression validation requires an exact fingerprint, reason, and expiration", () => {
  assert.throws(() => normalizeSuppressions([{ reason: "missing fingerprint", expiresAt: "2099-01-01" }]), /fingerprint/);
  assert.throws(() => normalizeSuppressions([{ fingerprint: "a", expiresAt: "2099-01-01" }]), /reason/);
  assert.throws(() => normalizeSuppressions([{ fingerprint: "a", reason: "missing expiration" }]), /expiresAt/);
});
