import test from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import { readFile, unlink } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { scan } from "../src/scanner.mjs";
import { assertInScope, normalizeScope } from "../src/scope.mjs";

function startFixture() {
  let receivedHeader = "";
  const server = http.createServer((request, response) => {
    receivedHeader = request.headers.authorization || "";
    if (request.url === "/app.js") {
      response.writeHead(200, { "content-type": "application/javascript" });
      response.end("fetch('/api/orders'); //# sourceMappingURL=app.js.map");
      return;
    }
    if (request.url?.startsWith("/data.json")) {
      response.writeHead(200, { "content-type": "application/json" });
      response.end(JSON.stringify({ user: { token: "visible-to-client" } }));
      return;
    }
    response.writeHead(200, {
      "content-type": "text/html",
      "content-security-policy": "default-src * 'unsafe-inline'",
      "access-control-allow-origin": "*",
      "access-control-allow-credentials": "true",
    });
    response.end(`
      <script src="/app.js"></script>
      <script>fetch('/api/users'); const apiKey = "abcdefghijklmnopqrstuv";</script>
      <a href="/data.json?next=https%3A%2F%2Fevil.example">data</a>
    `);
  });
  return new Promise((resolve) => server.listen(0, "127.0.0.1", () => resolve({ server, getHeader: () => receivedHeader })));
}

test("scope supports wildcard subdomains, multiple origins, and path boundaries", () => {
  const scope = normalizeScope({
    allowedOrigins: ["https://*.example.test", "https://second.test"],
    includePaths: ["/public"],
    excludePaths: ["/public/private"],
  });
  assertInScope("https://one.example.test/public/file", scope);
  assertInScope("https://second.test/public", scope);
  assert.throws(() => assertInScope("https://example.test/public", scope), /Out-of-scope navigation/);
  assert.throws(() => assertInScope("https://one.example.test/private", scope), /Out-of-scope path/);
  assert.throws(() => assertInScope("https://one.example.test/public/private", scope), /Excluded path/);
});

test("scan inventories client APIs and JSON, preserves auth headers, and checkpoints completion", async (t) => {
  const fixture = await startFixture();
  t.after(() => fixture.server.close());
  const { port } = fixture.server.address();
  const target = `http://127.0.0.1:${port}/`;
  const checkpointPath = join(tmpdir(), `sentinelscan-test-${process.pid}.json`);
  t.after(() => unlink(checkpointPath).catch(() => {}));
  const report = await scan(target, {
    maxPages: 3,
    maxResources: 5,
    delayMs: 0,
    authHeaders: { authorization: "Bearer test-session" },
    checkpointPath,
    scope: { name: "fixture", allowedOrigins: [`http://127.0.0.1:${port}`] },
  });
  const ids = new Set(report.findings.map((item) => item.id));
  assert.equal(fixture.getHeader(), "Bearer test-session");
  assert.ok(ids.has("weak-content-security-policy"));
  assert.ok(ids.has("cors-wildcard-with-credentials"));
  assert.ok(ids.has("potential-open-redirect"));
  assert.ok(ids.has("potential-client-secret"));
  assert.ok(ids.has("sensitive-data-in-json"));
  assert.ok(ids.has("public-source-map-reference"));
  assert.ok(report.inventory.totals.clientApiEndpoints.length >= 2);
  assert.equal(report.summary.resourcesScanned, 2);
  assert.equal(report.scanner.version, "0.5.1");
  const checkpoint = JSON.parse(await readFile(checkpointPath, "utf8"));
  assert.equal(checkpoint.status, "complete");
  assert.equal(checkpoint.report.summary.findings, report.summary.findings);

  const budgetReport = await scan(target, {
    maxPages: 3,
    maxResources: 5,
    maxRequests: 1,
    delayMs: 0,
    scope: { name: "fixture", allowedOrigins: [`http://127.0.0.1:${port}`] },
  });
  assert.equal(budgetReport.summary.requestsMade, 1);
  assert.equal(budgetReport.summary.termination, "Maximum request budget reached.");
});
