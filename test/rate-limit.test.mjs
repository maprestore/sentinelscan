import test from "node:test";
import assert from "node:assert/strict";
import { RateLimiter } from "../src/rate-limit.mjs";

test("rate limiter returns a bounded retry interval and expires entries", () => {
  const limiter = new RateLimiter({ windowMs: 100, max: 2, maxKeys: 2 });
  assert.equal(limiter.check("client", 0).allowed, true);
  assert.equal(limiter.check("client", 1).allowed, true);
  const blocked = limiter.check("client", 2);
  assert.equal(blocked.allowed, false);
  assert.ok(blocked.retryAfterMs > 0 && blocked.retryAfterMs <= 100);
  assert.equal(limiter.check("client", 101).allowed, true);
});

test("rate limiter bounds retained keys", () => {
  const limiter = new RateLimiter({ max: 1, maxKeys: 2 });
  limiter.check("one", 0);
  limiter.check("two", 0);
  limiter.check("three", 0);
  assert.ok(limiter.entries.size <= 2);
});
