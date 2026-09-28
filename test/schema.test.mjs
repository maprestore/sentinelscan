import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { join } from "node:path";

const root = new URL("../", import.meta.url);
const schemaNames = ["finding", "suppressions", "scope", "config", "checkpoint", "report"];

test("all public JSON schemas are valid JSON with stable identifiers", async () => {
  for (const name of schemaNames) {
    const schema = JSON.parse(await readFile(new URL(`schemas/${name}.schema.json`, root), "utf8"));
    assert.equal(schema.$schema, "https://json-schema.org/draft/2020-12/schema");
    assert.match(schema.$id, new RegExp(`${name}\\.schema\\.json$`));
    assert.equal(schema.type, name === "suppressions" ? "array" : "object");
  }
});

test("report schema requires triage-aware finding counts", async () => {
  const schema = JSON.parse(await readFile(new URL("schemas/report.schema.json", root), "utf8"));
  assert.deepEqual(schema.properties.summary.required, ["findings", "actionableFindings", "suppressedFindings"]);
  assert.equal(schema.properties.schemaVersion.const, 2);
});

test("package metadata exposes the typed entry point", async () => {
  const packageJson = JSON.parse(await readFile(join(new URL("../", import.meta.url).pathname, "package.json"), "utf8"));
  assert.equal(packageJson.types, "./index.d.ts");
  assert.equal(packageJson.exports["."].import, "./src/index.mjs");
});
