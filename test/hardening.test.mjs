import test from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import { readFile, unlink } from "node:fs/promises";
import { join } from "node:path";
import { assertInScope, normalizeScope } from "../src/scope.mjs";
import { compareReports } from "../src/baseline.mjs";
import { normalizeTarget, redactUrl, scan } from "../src/scanner.mjs";

function startSite(handler) {
  const server = http.createServer(handler);
  return new Promise((resolve) => server.listen(0, "127.0.0.1", () => resolve(server)));
}

test("the library engine requires an explicit authorization acknowledgement", async () => {
  await assert.rejects(
    () => scan("http://127.0.0.1:9/", { scope: { allowedOrigins: ["http://127.0.0.1:9"] } }),
    /explicit authorization/,
  );
});

test("the root include path covers descendants and exclusions still win", () => {
  const scope = normalizeScope({ allowedOrigins: ["https://example.test"], includePaths: ["/"], excludePaths: ["/private"] });
  assertInScope("https://example.test/", scope);
  assertInScope("https://example.test/app/settings", scope);
  assert.throws(() => assertInScope("https://example.test/private/file", scope), /Excluded path/);
});

test("scope matching decodes paths and keeps exact placeholder hosts exact", () => {
  const scope = normalizeScope({ allowedOrigins: ["https://example.test"], excludePaths: ["/logout"] });
  assert.throws(() => assertInScope("https://example.test/%6cogout", scope), /Excluded path/);
  assert.throws(() => assertInScope("https://example.test/%256cogout", scope), /Excluded path/);
  assert.throws(() => assertInScope("https://example.test/%252525252525256cogout", scope), /Excluded path/);

  const exact = normalizeScope({ allowedOrigins: ["https://placeholder.com"] });
  assertInScope("https://placeholder.com/", exact);
  assert.throws(() => assertInScope("https://evil.com/", exact), /Out-of-scope/);

  const wildcard = normalizeScope({ allowedOrigins: ["https://*.example.test"] });
  assertInScope("https://app.example.test/", wildcard);
  assert.throws(() => assertInScope("https://example.test/", wildcard), /Out-of-scope/);
  assert.throws(() => normalizeScope({ allowedOrigins: ["https://*."] }), /wildcard/);
});

test("target and report URL handling removes nested credentials and fragments", () => {
  assert.equal(redactUrl("https://example.test/callback#access_token=secret-value"), "https://example.test/callback");
  assert.throws(
    () => normalizeTarget("https://example.test/?next=https%3A%2F%2Fevil.test%2F%3Ftoken%3Dsecret-value"),
    /credential-shaped query parameters/,
  );
  assert.throws(
    () => normalizeTarget("https://example.test/?next=https%3A%2F%2Fevil.test%2F%23access_token%3Dsecret-value"),
    /credential-shaped query parameters/,
  );
  assert.throws(
    () => normalizeTarget("https://example.test/?next=access_token%253Dsecret-value"),
    /credential-shaped query parameters/,
  );
});

test("independent page and resource budgets still inspect queued resources", async (t) => {
  const server = await startSite((request, response) => {
    if (request.url === "/app.js") {
      response.writeHead(200, { "content-type": "application/javascript" });
      return response.end("console.log('fixture');");
    }
    response.writeHead(200, { "content-type": "text/html" });
    return response.end("<script src=/app.js></script><a href=/child>child</a>");
  });
  t.after(() => server.close());
  const origin = `http://127.0.0.1:${server.address().port}`;
  const report = await scan(`${origin}/`, {
    confirmAuthorized: true,
    allowPrivateNetwork: true,
    maxPages: 1,
    maxResources: 1,
    maxRequests: 20,
    delayMs: 0,
    scope: { allowedOrigins: [origin] },
  });
  assert.equal(report.summary.pagesScanned, 1);
  assert.equal(report.summary.resourcesScanned, 1);
});

test("default form methods are treated as GET and nested URL secrets are redacted", async (t) => {
  const server = await startSite((request, response) => {
    response.writeHead(200, { "content-type": "text/html" });
    response.end('<form action="/login"><input type=password name=password></form><a href="/go?next=https%3A%2F%2Fevil.test%2F%3Ftoken%3Dsecret-value">go</a>');
  });
  t.after(() => server.close());
  const origin = `http://127.0.0.1:${server.address().port}`;
  const report = await scan(`${origin}/`, { confirmAuthorized: true, allowPrivateNetwork: true, delayMs: 0, scope: { allowedOrigins: [origin] } });
  assert.ok(report.findings.some((item) => item.id === "credential-form-uses-get"));
  const redirect = report.findings.find((item) => item.id === "potential-open-redirect");
  assert.ok(redirect);
  assert.doesNotMatch(redirect.evidence, /secret-value/);
  assert.match(redirect.evidence, /REDACTED/);
});

test("extensionless API links respect the resource budget", async (t) => {
  const requested = [];
  const server = await startSite((request, response) => {
    requested.push(request.url);
    if (request.url === "/") {
      response.writeHead(200, { "content-type": "text/html" });
      return response.end('<a href="/api/one">one</a><a href="/api/two">two</a>');
    }
    response.writeHead(200);
    return response.end('{"token":"not-a-secret"}');
  });
  t.after(() => server.close());
  const origin = `http://127.0.0.1:${server.address().port}`;
  const report = await scan(`${origin}/`, {
    confirmAuthorized: true,
    allowPrivateNetwork: true,
    maxPages: 1,
    maxResources: 1,
    maxRequests: 20,
    delayMs: 0,
    scope: { allowedOrigins: [origin] },
  });
  assert.equal(report.summary.resourcesScanned, 1);
  assert.equal(requested.filter((url) => url.startsWith("/api/")).length, 1);
});

test("unknown scan options do not enter report limits", async (t) => {
  const server = await startSite((request, response) => {
    response.writeHead(200, { "content-type": "text/html" });
    response.end("<p>fixture</p>");
  });
  t.after(() => server.close());
  const origin = `http://127.0.0.1:${server.address().port}`;
  const report = await scan(`${origin}/`, {
    confirmAuthorized: true,
    allowPrivateNetwork: true,
    maxPages: 1,
    maxResources: 1,
    maxRequests: 1,
    delayMs: 0,
    apiKey: "should-not-appear",
    scope: { allowedOrigins: [origin] },
  });
  assert.equal(report.limits.apiKey, undefined);
  assert.doesNotMatch(JSON.stringify(report), /should-not-appear/);
});

test("custom infrastructure email domains must be explicitly included in scope", async () => {
  await assert.rejects(
    () => scan("http://127.0.0.1:9/", {
      confirmAuthorized: true,
      allowPrivateNetwork: true,
      checkInfrastructure: true,
      emailDomain: "outside.example",
      scope: { allowedOrigins: ["http://127.0.0.1:9"] },
    }),
    /emailDomain must be included in the explicit scan scope/,
  );
});

test("budget-stopped checkpoints preserve deferred work for a later resume", async (t) => {
  const server = await startSite((request, response) => {
    response.writeHead(200, { "content-type": "text/html" });
    response.end(`<a href="/one">one</a><a href="/two">two</a>`);
  });
  t.after(() => server.close());
  const origin = `http://127.0.0.1:${server.address().port}`;
  const checkpoint = join(process.cwd(), `.sentinelscan-hardening-${process.pid}.json`);
  t.after(() => unlink(checkpoint).catch(() => {}));
  const report = await scan(`${origin}/`, {
    confirmAuthorized: true,
    allowPrivateNetwork: true,
    maxPages: 1,
    maxResources: 1,
    maxRequests: 20,
    delayMs: 0,
    checkpointPath: checkpoint,
    scope: { allowedOrigins: [origin] },
  });
  const saved = JSON.parse(await readFile(checkpoint, "utf8"));
  assert.match(report.summary.termination, /Maximum page budget/);
  assert.equal(saved.status, "in-progress");
  assert.ok(saved.deferred.length >= 1);
  const resumed = await scan(`${origin}/`, {
    confirmAuthorized: true,
    allowPrivateNetwork: true,
    maxPages: 3,
    maxResources: 3,
    maxRequests: 100,
    delayMs: 0,
    resume: saved,
    scope: { allowedOrigins: [origin] },
  });
  assert.equal(resumed.summary.pagesScanned, 3);
  assert.equal(resumed.summary.termination, "queue-exhausted");
});

test("budget-stopped metadata resumes at the next well-known path", async (t) => {
  const requested = [];
  const server = await startSite((request, response) => {
    requested.push(request.url);
    response.writeHead(200, { "content-type": request.url === "/" ? "text/html" : "text/plain" });
    response.end(request.url === "/" ? "<p>fixture</p>" : "ok");
  });
  t.after(() => server.close());
  const origin = `http://127.0.0.1:${server.address().port}`;
  const checkpoint = join(process.cwd(), `.sentinelscan-metadata-${process.pid}.json`);
  t.after(() => unlink(checkpoint).catch(() => {}));
  const first = await scan(`${origin}/`, {
    confirmAuthorized: true,
    allowPrivateNetwork: true,
    maxPages: 1,
    maxResources: 1,
    maxRequests: 2,
    delayMs: 0,
    checkpointPath: checkpoint,
    scope: { allowedOrigins: [origin] },
  });
  const saved = JSON.parse(await readFile(checkpoint, "utf8"));
  assert.match(first.summary.termination, /Maximum request budget/);
  assert.equal(saved.wellKnownIndex, 1);
  const resumed = await scan(`${origin}/`, {
    confirmAuthorized: true,
    allowPrivateNetwork: true,
    maxPages: 1,
    maxResources: 1,
    maxRequests: 20,
    delayMs: 0,
    resume: saved,
    scope: { allowedOrigins: [origin] },
  });
  assert.equal(resumed.summary.termination, "queue-exhausted");
  assert.equal(requested.filter((url) => url === "/robots.txt").length, 1);
});

test("baselines reject reports for different targets or scopes", () => {
  const report = { target: "https://one.test/", scope: { allowedOrigins: ["https://one.test"] }, findings: [] };
  assert.throws(() => compareReports(report, { ...report, target: "https://two.test/" }), /same URL/);
  assert.throws(() => compareReports(report, { ...report, scope: { allowedOrigins: ["https://other.test"] } }), /same scope/);
});

test("resume checkpoints validate request counters before continuing", async () => {
  await assert.rejects(
    () => scan("https://example.test/", {
      confirmAuthorized: true,
      scope: { allowedOrigins: ["https://example.test"] },
      resume: {
        schemaVersion: 2,
        status: "in-progress",
        target: "https://example.test/",
        scope: { allowedOrigins: ["https://example.test"] },
        requestCount: "1",
      },
    }),
    /requestCount must be a non-negative integer/,
  );
  await assert.rejects(
    () => scan("https://example.test/", {
      confirmAuthorized: true,
      maxRequests: 10,
      scope: { allowedOrigins: ["https://example.test"] },
      resume: {
        schemaVersion: 2,
        status: "in-progress",
        target: "https://example.test/",
        scope: { allowedOrigins: ["https://example.test"] },
        requestCount: 11,
      },
    }),
    /requestCount exceeds the configured scan request budget/,
  );
});

test("the elapsed budget bounds an in-flight request", async (t) => {
  const server = await startSite(() => {});
  t.after(() => server.close());
  const origin = `http://127.0.0.1:${server.address().port}`;
  const started = performance.now();
  const report = await scan(`${origin}/`, {
    confirmAuthorized: true,
    allowPrivateNetwork: true,
    maxElapsedMs: 100,
    maxRequests: 1,
    timeoutMs: 5_000,
    delayMs: 0,
    scope: { allowedOrigins: [origin] },
  });
  assert.match(report.summary.termination, /Maximum scan duration/);
  assert.ok(performance.now() - started < 1_000);
});
