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
  assert.equal(health.version, "0.5.1");
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

test("dashboard can protect scan APIs with an optional bearer token", async (t) => {
  const dashboardPort = 4500 + (process.pid % 200);
  const dashboard = spawn(process.execPath, [new URL("../src/server.mjs", import.meta.url).pathname], {
    env: { ...process.env, PORT: String(dashboardPort), SENTINELSCAN_API_TOKEN: "test-token" },
    stdio: "ignore",
  });
  t.after(() => dashboard.kill("SIGTERM"));

  const health = await waitForHealth(dashboardPort);
  assert.equal(health.authRequired, true);

  const unauthorized = await fetch(`http://127.0.0.1:${dashboardPort}/api/scans`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({}),
  });
  assert.equal(unauthorized.status, 401);
  assert.match(unauthorized.headers.get("www-authenticate"), /Bearer/);

  const authorized = await fetch(`http://127.0.0.1:${dashboardPort}/api/scans`, {
    method: "POST",
    headers: { "content-type": "application/json", authorization: "Bearer test-token" },
    body: JSON.stringify({}),
  });
  assert.equal(authorized.status, 400);
});

test("dashboard rejects malformed and oversized JSON with client errors", async (t) => {
  const dashboardPort = 4700 + (process.pid % 200);
  const dashboard = spawn(process.execPath, [new URL("../src/server.mjs", import.meta.url).pathname], {
    env: { ...process.env, PORT: String(dashboardPort) },
    stdio: "ignore",
  });
  t.after(() => dashboard.kill("SIGTERM"));
  await waitForHealth(dashboardPort);

  const malformed = await fetch(`http://127.0.0.1:${dashboardPort}/api/scans`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: "{",
  });
  assert.equal(malformed.status, 400);

  const oversized = await fetch(`http://127.0.0.1:${dashboardPort}/api/scans`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ value: "x".repeat(17_000) }),
  });
  assert.equal(oversized.status, 413);
});
