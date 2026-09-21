import test from "node:test";
import assert from "node:assert/strict";
import { scan } from "../src/scanner.mjs";
import { createWeakSite } from "../examples/weak-site.mjs";

test("the bundled weak demo site produces the findings shown in the README", async (t) => {
  const server = createWeakSite();
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  t.after(() => server.close());
  const { port } = server.address();
  const origin = `http://127.0.0.1:${port}`;

  const report = await scan(`${origin}/`, {
    delayMs: 0,
    scope: { name: "local-weak-demo", allowedOrigins: [origin] },
  });
  const ids = new Set(report.findings.map((item) => item.id));

  for (const expected of [
    "site-served-over-http",
    "credential-form-over-http",
    "credential-form-uses-get",
    "exposed-git-metadata",
    "external-script-without-sri",
    "missing-content-security-policy",
    "cookie-missing-httponly",
    "client-api-endpoint",
    "robots-discloses-sensitive-path",
  ]) {
    assert.ok(ids.has(expected), `expected finding ${expected}`);
  }
  assert.ok(report.attackPaths.some((path) => path.id === "credential-interception-path"));
  assert.equal(report.risk.grade, "F");
  assert.ok(report.pages.every((page) => page.finalUrl.startsWith(origin)));
});
