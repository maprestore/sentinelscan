import test from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtemp, writeFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

const root = new URL("../", import.meta.url).pathname;
const cli = join(root, "src/cli.mjs");

test("validate command accepts config without making network requests", () => {
  const result = spawnSync(process.execPath, [cli, "validate", "config", join(root, "config.example.json"), "--json"], { encoding: "utf8" });
  assert.equal(result.status, 0);
  const output = JSON.parse(result.stdout);
  assert.equal(output.valid, true);
  assert.equal(output.type, "config");
});

test("validate command returns machine-readable failures", async (t) => {
  const directory = await mkdtemp(join(tmpdir(), "sentinelscan-validate-"));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const path = join(directory, "bad.json");
  await writeFile(path, JSON.stringify({ maxRequests: 5_001 }));
  const result = spawnSync(process.execPath, [cli, "validate", "config", path, "--json"], { encoding: "utf8" });
  assert.equal(result.status, 1);
  const output = JSON.parse(result.stdout);
  assert.equal(output.valid, false);
  assert.equal(output.error.code, "INVALID_ARTIFACT");
  assert.match(output.error.path, /maxRequests/);
});
