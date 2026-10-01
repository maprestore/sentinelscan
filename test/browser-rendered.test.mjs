import test from "node:test";
import assert from "node:assert/strict";
import { scan } from "../src/scanner.mjs";
import { readBoundedBody } from "../src/browser-renderer.mjs";

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

test("rendered response bodies are capped before they are handed to the browser", async () => {
  let canceled = false;
  const response = new Response(new ReadableStream({
    start(controller) {
      controller.enqueue(new Uint8Array([1, 2, 3]));
      controller.enqueue(new Uint8Array([4, 5, 6]));
    },
    cancel() { canceled = true; },
  }));
  const body = await readBoundedBody(response, 5);
  assert.deepEqual([...body.bytes], [1, 2, 3, 4, 5]);
  assert.equal(body.truncated, true);
  assert.equal(canceled, true);
});

test("rendered body reader stops immediately when the scan is canceled", async () => {
  const controller = new AbortController();
  controller.abort(new DOMException("Canceled", "AbortError"));
  let canceled = false;
  const response = new Response(new ReadableStream({
    start() {},
    cancel() { canceled = true; },
  }));
  await assert.rejects(() => readBoundedBody(response, 10, controller.signal), { name: "AbortError" });
  assert.equal(canceled, true);
});
