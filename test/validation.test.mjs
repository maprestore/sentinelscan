import test from "node:test";
import assert from "node:assert/strict";
import { addIntegrity } from "../src/provenance.mjs";
import { scan } from "../src/scanner.mjs";
import { validateArtifact, validateConfig } from "../src/validation.mjs";
import { createWeakSite } from "../examples/weak-site.mjs";

test("generated reports carry verifiable integrity, identity, and coverage", async (t) => {
  const fixture = createWeakSite();
  await new Promise((resolve) => fixture.listen(0, "127.0.0.1", resolve));
  t.after(() => fixture.close());
  const { port } = fixture.address();
  const target = `http://127.0.0.1:${port}/`;
  const report = await scan(target, {
    confirmAuthorized: true,
    allowPrivateNetwork: true,
    scope: { allowedOrigins: [`http://127.0.0.1:${port}`] },
    maxPages: 1,
    maxResources: 1,
    maxRequests: 10,
    delayMs: 0,
  });
  assert.equal(report.integrity.algorithm, "sha256");
  assert.match(report.integrity.contentHash, /^[a-f0-9]{64}$/);
  assert.match(report.scanIdentity.value, /^[a-f0-9]{64}$/);
  assert.equal(validateArtifact("report", report).integrity, "verified");
  const tampered = { ...report, target: `${target}changed` };
  assert.throws(() => validateArtifact("report", tampered), /content hash does not match/);
  const checkpoint = addIntegrity({ schemaVersion: 2, status: "complete", target, scope: report.scope, report: { ...report, risk: { ...report.risk, score: 0 } } });
  await assert.rejects(() => scan(target, { confirmAuthorized: true, allowPrivateNetwork: true, scope: report.scope, resume: checkpoint }), /report integrity hash/);
});

test("config validation rejects unknown keys and unsafe limit expansion", () => {
  assert.doesNotThrow(() => validateConfig({ maxPages: 10, maxRequests: 100, exitPolicy: { failOnIncomplete: true } }));
  assert.throws(() => validateConfig({ secretFeature: true }), /not a supported property/);
  assert.throws(() => validateConfig({ maxRequests: 5_001 }), /maxRequests/);
  assert.throws(() => validateConfig({ rendered: true, confirmRendered: false }), /confirmRendered/);
});

test("checkpoint validation verifies its integrity without contacting a target", () => {
  const checkpoint = addIntegrity({
    schemaVersion: 2,
    status: "in-progress",
    target: "http://127.0.0.1:4599/",
    scope: { allowedOrigins: ["http://127.0.0.1:4599"] },
    queued: [],
    findings: [],
  });
  assert.equal(validateArtifact("checkpoint", checkpoint).integrity, "verified");
  assert.throws(() => validateArtifact("checkpoint", { ...checkpoint, requestCount: 1 }), /content hash does not match/);
});
