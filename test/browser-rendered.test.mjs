import test from "node:test";
import assert from "node:assert/strict";
import { scan } from "../src/scanner.mjs";

test("rendered mode requires a separate explicit acknowledgement", async () => {
  await assert.rejects(
    () => scan("https://example.test/", { confirmAuthorized: true, rendered: true, scope: { allowedOrigins: ["https://example.test"] } }),
    /confirmRendered/,
  );
});

test("rendered mode reports a clear optional-browser error when Playwright is unavailable", async () => {
  try {
    const report = await scan("https://example.test/", {
      confirmAuthorized: true,
      rendered: true,
      confirmRendered: true,
      maxPages: 1,
      maxResources: 1,
      maxRequests: 2,
      maxElapsedMs: 2_000,
      delayMs: 0,
      scope: { allowedOrigins: ["https://example.test"] },
    });
    assert.equal(report.scanner.mode, "bounded-rendered");
  } catch (error) {
    assert.equal(error.code, "BROWSER_MODE_UNAVAILABLE");
  }
});
