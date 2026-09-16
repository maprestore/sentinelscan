import test from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import { normalizeTarget, scan } from "../src/scanner.mjs";

function startFixture() {
  const server = http.createServer((request, response) => {
    if (request.url === "/.git/HEAD") {
      response.writeHead(200, { "content-type": "text/plain" });
      response.end("ref: refs/heads/main\n");
      return;
    }
    if (request.url === "/robots.txt") {
      response.writeHead(200, { "content-type": "text/plain" });
      response.end("User-agent: *\nDisallow: /admin\n");
      return;
    }
    if (request.url === "/sitemap.xml") {
      response.writeHead(404);
      response.end();
      return;
    }
    if (request.url === "/.well-known/security.txt") {
      response.writeHead(404);
      response.end();
      return;
    }
    response.writeHead(200, {
      "content-type": "text/html",
      server: "fixture/1.0",
      "set-cookie": "session=demo",
    });
    response.end(`
      <html><body>
        <form action="http://example.test/login"><input type="password" name="password"></form>
        <script src="https://cdn.example.test/app.js"></script>
        <a href="/about">About</a>
      </body></html>
    `);
  });
  return new Promise((resolve) => server.listen(0, "127.0.0.1", () => resolve(server)));
}

test("normalizeTarget accepts web URLs and rejects unsafe schemes", () => {
  assert.equal(normalizeTarget("https://example.test/a#fragment").href, "https://example.test/a");
  assert.throws(() => normalizeTarget("file:///tmp/test"), /http/);
  assert.throws(() => normalizeTarget("https://user:pass@example.test"), /embedded/);
});

test("scan finds posture issues without submitting forms or leaving the origin", async (t) => {
  const server = await startFixture();
  t.after(() => server.close());
  const { port } = server.address();
  const target = `http://127.0.0.1:${port}/`;
  await assert.rejects(
    () => scan(target, { scope: { allowedOrigins: ["https://outside.example"] } }),
    /Out-of-scope navigation blocked/,
  );
  const report = await scan(target, {
    maxPages: 3,
    delayMs: 0,
    scope: { name: "local-fixture", allowedOrigins: [`http://127.0.0.1:${port}`] },
  });
  const ids = new Set(report.findings.map((item) => item.id));

  assert.equal(report.summary.pagesScanned, 2);
  assert.ok(ids.has("site-served-over-http"));
  assert.ok(ids.has("credential-form-over-http"));
  assert.ok(ids.has("exposed-git-metadata"));
  assert.ok(ids.has("robots-discloses-sensitive-path"));
  assert.ok(ids.has("cookie-missing-httponly"));
  assert.ok(ids.has("external-script-without-sri"));
  assert.equal(report.scope.name, "local-fixture");
  assert.ok(report.attackPaths.some((path) => path.id === "credential-interception-path"));
  assert.ok(report.risk.score > 0);
  assert.equal(report.inventory.totals.passwordForms, 2);
  assert.ok(report.findings.every((item) => /^[a-f0-9]{16}$/.test(item.fingerprint)));
  assert.ok(report.pages.every((page) => page.finalUrl.startsWith(`http://127.0.0.1:${port}`)));
});
