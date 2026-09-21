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

const instance = (evidence) => ({ fingerprint: "shared", id: "cookie-missing-httponly", severity: "low", evidence });
const report = (...findings) => ({ target: "https://example.test", findings, risk: { score: 0 } });

test("findings that share a fingerprint are compared as separate instances", () => {
  const baseline = report(instance("cookie a"), instance("cookie b"));

  const worse = compareReports(report(instance("cookie a"), instance("cookie b"), instance("cookie c")), baseline);
  assert.equal(worse.summary.status, "regressed", "a third instance is a regression");
  assert.deepEqual([worse.summary.new, worse.summary.unchanged, worse.summary.resolved], [1, 2, 0]);
  assert.equal(worse.newFindings[0].evidence, "cookie c");

  const better = compareReports(report(instance("cookie b")), baseline);
  assert.equal(better.summary.status, "improved", "fixing one of two instances is an improvement");
  assert.deepEqual([better.summary.new, better.summary.unchanged, better.summary.resolved], [0, 1, 1]);
  assert.equal(better.resolvedFindings[0].evidence, "cookie a");

  const same = compareReports(report(instance("cookie b"), instance("cookie a")), baseline);
  assert.equal(same.summary.status, "unchanged", "discovery order must not matter");
  assert.deepEqual([same.summary.new, same.summary.unchanged, same.summary.resolved], [0, 2, 0]);
});

test("instances with changed evidence are matched by count, not reported as churn", () => {
  const result = compareReports(report(instance("cookie a"), instance("cookie z")), report(instance("cookie a"), instance("cookie b")));
  assert.deepEqual([result.summary.new, result.summary.unchanged, result.summary.resolved], [0, 2, 0]);
  assert.equal(result.summary.status, "unchanged");
});

test("a severity change on a shared fingerprint is still detected per instance", () => {
  const raised = { ...instance("cookie a"), severity: "high" };
  const result = compareReports(report(raised, instance("cookie b")), report(instance("cookie a"), instance("cookie b")));
  assert.equal(result.summary.changed, 1);
  assert.equal(result.changedFindings[0].current.evidence, "cookie a");
  assert.equal(result.summary.status, "regressed");
});
