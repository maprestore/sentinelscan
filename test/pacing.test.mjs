import test from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import { scan } from "../src/scanner.mjs";

function startSite(handler) {
  const arrivals = [];
  const server = http.createServer((request, response) => {
    arrivals.push({ path: request.url, at: performance.now() });
    handler(request, response);
  });
  return new Promise((resolve) => server.listen(0, "127.0.0.1", () => resolve({ server, arrivals, origin: `http://127.0.0.1:${server.address().port}` })));
}

const html = (response, body) => {
  response.writeHead(200, { "content-type": "text/html" });
  response.end(body);
};

test("the request delay applies to every request: crawl, redirect hops, and well-known paths", async (t) => {
  const { server, arrivals, origin } = await startSite((request, response) => {
    if (request.url === "/") return html(response, '<a href="/moved">moved</a>');
    if (request.url === "/moved") {
      response.writeHead(302, { location: "/final" });
      return response.end();
    }
    if (request.url === "/final") return html(response, "<p>final</p>");
    response.writeHead(404);
    return response.end();
  });
  t.after(() => server.close());

  const delayMs = 80;
  const report = await scan(`${origin}/`, { delayMs, scope: { name: "pacing", allowedOrigins: [origin] } });

  const paths = arrivals.map((entry) => entry.path);
  assert.ok(paths.includes("/moved") && paths.includes("/final"), "the redirect hop should have been followed");
  assert.ok(paths.includes("/.git/HEAD") && paths.includes("/actuator/env"), "all nine well-known paths should have been checked");
  assert.ok(arrivals.length >= 12, `expected 12 or more requests, saw ${arrivals.length}`);
  assert.equal(report.summary.termination, "queue-exhausted");

  const gaps = arrivals.slice(1).map((entry, index) => entry.at - arrivals[index].at);
  const tolerance = 10; // timers and scheduling on a busy CI machine
  const tooFast = gaps.map((gap, index) => ({ from: arrivals[index].path, to: arrivals[index + 1].path, gap })).filter(({ gap }) => gap < delayMs - tolerance);
  assert.deepEqual(tooFast, [], "no two consecutive requests may be closer than the configured delay");
});

test("delayMs 0 sends requests back to back", async (t) => {
  const { server, arrivals, origin } = await startSite((request, response) => (request.url === "/" ? html(response, "<p>hi</p>") : (response.writeHead(404), response.end())));
  t.after(() => server.close());
  const started = performance.now();
  await scan(`${origin}/`, { delayMs: 0, scope: { name: "no-delay", allowedOrigins: [origin] } });
  assert.ok(arrivals.length >= 10);
  assert.ok(performance.now() - started < 1500, "ten local requests without a delay should be fast");
});

test("a request that times out becomes a finding; it does not abort the scan", async (t) => {
  const hanging = new Set();
  const { server, origin } = await startSite((request, response) => {
    if (request.url === "/") return html(response, '<a href="/slow">slow</a> <a href="/ok">ok</a>');
    if (request.url === "/slow") return hanging.add(response); // never answers
    if (request.url === "/ok") return html(response, "<p>ok</p>");
    response.writeHead(404);
    return response.end();
  });
  t.after(() => {
    for (const response of hanging) response.destroy();
    server.close();
  });

  const report = await scan(`${origin}/`, { delayMs: 0, timeoutMs: 150, scope: { name: "timeout", allowedOrigins: [origin] } });
  const failed = report.findings.filter((item) => item.id === "request-failed");
  assert.equal(failed.length, 1);
  assert.match(failed[0].evidence, /timed out after 150 ms/);
  assert.equal(report.summary.termination, "queue-exhausted");
  assert.ok(report.pages.some((page) => page.finalUrl.endsWith("/ok")), "pages after the slow one must still be scanned");
});

test("an operator cancellation still stops the scan, even while waiting between requests", async (t) => {
  const { server, origin } = await startSite((request, response) => (request.url === "/" ? html(response, '<a href="/a">a</a>') : (response.writeHead(404), response.end())));
  t.after(() => server.close());

  const controller = new AbortController();
  const started = performance.now();
  setTimeout(() => controller.abort(new DOMException("Canceled by operator.", "AbortError")), 150);
  await assert.rejects(
    scan(`${origin}/`, { delayMs: 5_000, signal: controller.signal, scope: { name: "cancel", allowedOrigins: [origin] } }),
    { name: "AbortError" },
  );
  assert.ok(performance.now() - started < 2_000, "cancellation must interrupt the delay instead of waiting it out");
});

test("the wall-clock budget is honored while pacing the well-known path checks", async (t) => {
  const { server, origin } = await startSite((request, response) => (request.url === "/" ? html(response, "<p>hi</p>") : (response.writeHead(404), response.end())));
  t.after(() => server.close());
  const started = performance.now();
  const report = await scan(`${origin}/`, { delayMs: 400, maxElapsedMs: 1_000, scope: { name: "budget", allowedOrigins: [origin] } });
  assert.match(report.summary.termination, /Maximum scan duration reached/);
  assert.ok(performance.now() - started < 2_500, "the scan must stop shortly after the time budget, not after all nine paths");
});
