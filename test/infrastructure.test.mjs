import test from "node:test";
import assert from "node:assert/strict";
import { inspectInfrastructure } from "../src/infrastructure.mjs";

test("DNS failures fail closed before TLS or public metadata checks", async () => {
  const result = await inspectInfrastructure("https://sentinelscan-does-not-exist.invalid/", { timeoutMs: 250 });
  assert.ok(result.metadata.dns);
  assert.ok(result.metadata.dns.error);
  assert.equal(result.metadata.tls, null);
  assert.match(result.skipped, /DNS resolution failed/);
});

test("literal local targets skip public infrastructure metadata", async () => {
  const result = await inspectInfrastructure("http://127.0.0.1:4599/", { timeoutMs: 250, allowPrivateNetwork: true });
  assert.equal(result.metadata.dns, null);
  assert.match(result.skipped, /Local or IP target/);
});
