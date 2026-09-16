import test from "node:test";
import assert from "node:assert/strict";
import { buildAttackPaths, calculateRisk } from "../src/risk.mjs";

test("risk scoring explains correlated attack paths", () => {
  const findings = [
    { id: "site-served-over-http", severity: "high", fingerprint: "http" },
    { id: "credential-form-over-http", severity: "high", fingerprint: "form" },
    { id: "missing-referrer-policy", severity: "low", fingerprint: "referrer" },
  ];
  const paths = buildAttackPaths(findings);
  const risk = calculateRisk(findings, paths);
  assert.equal(paths[0].id, "credential-interception-path");
  assert.equal(paths[0].findingFingerprints.length, 2);
  assert.equal(risk.factors.attackPathBonus, 6);
  assert.equal(risk.grade, "F");
  assert.deepEqual(new Set(risk.priority.slice(0, 2)), new Set(["http", "form"]));
});
