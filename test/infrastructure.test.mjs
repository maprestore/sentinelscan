import test from "node:test";
import assert from "node:assert/strict";
import { Resolver } from "node:dns/promises";
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

test("infrastructure DNS queries are cancellable and obey the per-query timeout", async () => {
  const original = {
    resolve4: Resolver.prototype.resolve4,
    resolve6: Resolver.prototype.resolve6,
    cancel: Resolver.prototype.cancel,
  };
  let canceled = false;
  Resolver.prototype.resolve4 = () => new Promise(() => {});
  Resolver.prototype.resolve6 = () => new Promise(() => {});
  Resolver.prototype.cancel = function cancel() { canceled = true; };
  try {
    const result = await inspectInfrastructure("http://timeout.example/", { timeoutMs: 10 });
    assert.match(result.metadata.dns.error, /timed out/i);
    assert.equal(canceled, true);
    assert.equal(result.metadata.tls, null);
  } finally {
    Resolver.prototype.resolve4 = original.resolve4;
    Resolver.prototype.resolve6 = original.resolve6;
    Resolver.prototype.cancel = original.cancel;
  }
});

test("CAA checks use the target hostname and preserve each CAA tag/value", async () => {
  const original = {
    resolve4: Resolver.prototype.resolve4,
    resolve6: Resolver.prototype.resolve6,
    resolveTxt: Resolver.prototype.resolveTxt,
    resolveCaa: Resolver.prototype.resolveCaa,
    cancel: Resolver.prototype.cancel,
  };
  const caaQueries = [];
  const noData = () => Object.assign(new Error("No data"), { code: "ENODATA" });
  Resolver.prototype.resolve4 = async () => ["8.8.8.8"];
  Resolver.prototype.resolve6 = async () => { throw noData(); };
  Resolver.prototype.resolveTxt = async () => { throw noData(); };
  Resolver.prototype.resolveCaa = async (domain) => {
    caaQueries.push(domain);
    return [{ critical: 128, issue: "ca.example", issuewild: "wild.example", iodef: "mailto:security@example.test" }];
  };
  Resolver.prototype.cancel = function cancel() {};
  try {
    const result = await inspectInfrastructure("http://app.example/", {
      timeoutMs: 1_000,
      emailDomain: "mail.example",
      dkimSelectors: [],
    });
    assert.deepEqual(caaQueries, ["app.example"]);
    assert.equal(result.metadata.email.domain, "mail.example");
    assert.equal(result.metadata.email.caaDomain, "app.example");
    assert.deepEqual(result.metadata.email.caa, [
      { flags: 128, tag: "issue", value: "ca.example" },
      { flags: 128, tag: "issuewild", value: "wild.example" },
      { flags: 128, tag: "iodef", value: "mailto:security@example.test" },
    ]);
    assert.equal(result.findings.some((finding) => finding.id === "missing-caa"), false);
  } finally {
    Resolver.prototype.resolve4 = original.resolve4;
    Resolver.prototype.resolve6 = original.resolve6;
    Resolver.prototype.resolveTxt = original.resolveTxt;
    Resolver.prototype.resolveCaa = original.resolveCaa;
    Resolver.prototype.cancel = original.cancel;
  }
});

test("private-network opt-in never relaxes the fixed crt.sh safety boundary", async () => {
  const original = {
    resolve4: Resolver.prototype.resolve4,
    resolve6: Resolver.prototype.resolve6,
    resolveTxt: Resolver.prototype.resolveTxt,
    resolveCaa: Resolver.prototype.resolveCaa,
    cancel: Resolver.prototype.cancel,
  };
  const noData = () => Object.assign(new Error("No data"), { code: "ENODATA" });
  Resolver.prototype.resolve4 = async (host) => host === "public.example" ? ["8.8.8.8"] : ["127.0.0.1"];
  Resolver.prototype.resolve6 = async () => { throw noData(); };
  Resolver.prototype.resolveTxt = async () => { throw noData(); };
  Resolver.prototype.resolveCaa = async () => { throw noData(); };
  Resolver.prototype.cancel = function cancel() {};
  try {
    const result = await inspectInfrastructure("http://public.example/", {
      timeoutMs: 1_000,
      allowPrivateNetwork: true,
      certificateTransparency: true,
      dkimSelectors: [],
    });
    assert.match(result.metadata.certificateTransparency.error, /private or non-public address/i);
  } finally {
    Resolver.prototype.resolve4 = original.resolve4;
    Resolver.prototype.resolve6 = original.resolve6;
    Resolver.prototype.resolveTxt = original.resolveTxt;
    Resolver.prototype.resolveCaa = original.resolveCaa;
    Resolver.prototype.cancel = original.cancel;
  }
});
