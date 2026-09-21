import test from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import { spawn } from "node:child_process";

function startFixture() {
  const server = http.createServer((request, response) => {
    response.writeHead(200, { "content-type": "text/html" });
    response.end("<html><body><a href='/about'>About</a></body></html>");
  });
  return new Promise((resolve) => server.listen(0, "127.0.0.1", () => resolve(server)));
}

async function waitForHealth(port) {
  for (let attempt = 0; attempt < 40; attempt += 1) {
    try {
      const response = await fetch(`http://127.0.0.1:${port}/api/health`);
      if (response.ok) return response.json();
    } catch {
      // The local server may still be starting.
    }
    await new Promise((resolve) => setTimeout(resolve, 25));
  }
  throw new Error("Dashboard server did not start.");
}

test("dashboard exposes an asynchronous scan job with progress and a final report", async (t) => {
  const fixture = await startFixture();
  const dashboardPort = 4300 + (process.pid % 200);
  const dashboard = spawn(process.execPath, [new URL("../src/server.mjs", import.meta.url).pathname], {
    env: { ...process.env, PORT: String(dashboardPort) },
    stdio: "ignore",
  });
  t.after(() => {
    dashboard.kill("SIGTERM");
    fixture.close();
  });

  const health = await waitForHealth(dashboardPort);
  assert.equal(health.version, "0.5.0");
  const { port } = fixture.address();
  const target = `http://127.0.0.1:${port}/`;
  const started = await fetch(`http://127.0.0.1:${dashboardPort}/api/scans`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      target,
      confirmAuthorized: true,
      maxPages: 2,
      maxResources: 1,
      maxRequests: 20,
      delayMs: 0,
      scope: { name: "server-fixture", allowedOrigins: [`http://127.0.0.1:${port}`] },
    }),
  });
  assert.equal(started.status, 202);
  const { id } = await started.json();
  let final;
  for (let attempt = 0; attempt < 80; attempt += 1) {
    const response = await fetch(`http://127.0.0.1:${dashboardPort}/api/scans/${id}`);
    final = await response.json();
    if (["complete", "error", "canceled"].includes(final.status)) break;
    await new Promise((resolve) => setTimeout(resolve, 25));
  }
  assert.equal(final.status, "complete");
  assert.equal(final.report.target, target);
  assert.ok(final.progress.requestsMade >= 1);
  assert.equal(final.report.summary.termination, "queue-exhausted");
});

test("dashboard reports invalid requests as client errors, not server faults", async (t) => {
  const port = 4500 + (process.pid % 200);
  const dashboard = spawn(process.execPath, [new URL("../src/server.mjs", import.meta.url).pathname], {
    env: { ...process.env, PORT: String(port) },
    stdio: "ignore",
  });
  t.after(() => dashboard.kill("SIGTERM"));
  await waitForHealth(port);

  const post = async (path, body, raw = false) => {
    const response = await fetch(`http://127.0.0.1:${port}${path}`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: raw ? body : JSON.stringify(body),
    });
    return { status: response.status, body: await response.json() };
  };
  const target = "http://127.0.0.1:9/";

  for (const path of ["/api/scans", "/api/scan"]) {
    const missingConfirmation = await post(path, { target });
    assert.equal(missingConfirmation.status, 400, `${path}: missing confirmation`);
    assert.match(missingConfirmation.body.error, /explicit authorization/);

    const outOfScope = await post(path, { target, confirmAuthorized: true, scope: { allowedOrigins: ["https://other.example"] } });
    assert.equal(outOfScope.status, 400, `${path}: target outside the scope`);
    assert.match(outOfScope.body.error, /Out-of-scope/);

    const badTarget = await post(path, { target: "ftp://example.test/", confirmAuthorized: true });
    assert.equal(badTarget.status, 400, `${path}: unsupported scheme`);

    const badHeaders = await post(path, { target, confirmAuthorized: true, authHeaders: { host: "evil.example" } });
    assert.equal(badHeaders.status, 400, `${path}: forbidden auth header`);

    const notJson = await post(path, "not json", true);
    assert.equal(notJson.status, 400, `${path}: malformed JSON`);
    assert.match(notJson.body.error, /valid JSON/);

    const notObject = await post(path, "[1,2,3]", true);
    assert.equal(notObject.status, 400, `${path}: JSON that is not an object`);

    const tooLarge = await post(path, JSON.stringify({ target, confirmAuthorized: true, padding: "x".repeat(20_000) }), true);
    assert.equal(tooLarge.status, 413, `${path}: body over the 16 KB cap`);
  }

  const unknownJob = await fetch(`http://127.0.0.1:${port}/api/scans/00000000-0000-0000-0000-000000000000`);
  assert.equal(unknownJob.status, 404);
  const nothing = await fetch(`http://127.0.0.1:${port}/api/nope`);
  assert.equal(nothing.status, 404);
});
