import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { MAX_SCAN_LIMITS } from "../src/scanner.mjs";

const root = new URL("../", import.meta.url);
const schemaNames = ["finding", "suppressions", "scope", "config", "checkpoint", "report"];
const readSchema = async (name) => JSON.parse(await readFile(new URL(`schemas/${name}.schema.json`, root), "utf8"));

function assertSchemaPatterns(value, name) {
  if (Array.isArray(value)) {
    value.forEach((entry) => assertSchemaPatterns(entry, name));
    return;
  }
  if (!value || typeof value !== "object") return;
  if (typeof value.pattern === "string") assert.doesNotThrow(() => new RegExp(value.pattern), `${name}: ${value.pattern}`);
  Object.values(value).forEach((entry) => assertSchemaPatterns(entry, name));
}

test("all public JSON schemas are valid JSON with stable identifiers", async () => {
  for (const name of schemaNames) {
    const schema = JSON.parse(await readFile(new URL(`schemas/${name}.schema.json`, root), "utf8"));
    assert.equal(schema.$schema, "https://json-schema.org/draft/2020-12/schema");
    assert.match(schema.$id, new RegExp(`${name}\\.schema\\.json$`));
    assert.equal(schema.type, name === "suppressions" ? "array" : "object");
    assertSchemaPatterns(schema, name);
  }
});

test("report schema requires fields validated on generated reports", async () => {
  const schema = await readSchema("report");
  assert.deepEqual(schema.required, ["schemaVersion", "scanner", "target", "scope", "startedAt", "finishedAt", "limits", "scanIdentity", "coverage", "integrity", "summary", "pages", "resources", "requests", "infrastructure", "inventory", "findings", "suppressions", "attackPaths", "risk", "notes"]);
  assert.deepEqual(schema.properties.summary.required, ["pagesScanned", "resourcesScanned", "requestsMade", "elapsedMs", "termination", "findings", "actionableFindings", "suppressedFindings"]);
  for (const field of ["pages", "resources", "requests", "infrastructure", "inventory", "suppressions", "notes"]) assert.ok(schema.required.includes(field));
  assert.ok(schema.required.includes("scanIdentity"));
  assert.ok(schema.required.includes("coverage"));
  assert.ok(schema.required.includes("integrity"));
  assert.equal(schema.properties.schemaVersion.const, 2);
});

test("published scan bounds match source hard limits and validation", async () => {
  const config = await readSchema("config");
  const report = await readSchema("report");
  const checkpoint = await readSchema("checkpoint");
  const reportLimits = report.properties.limits.properties;
  const minimums = { maxRedirects: 0, delayMs: 0 };

  for (const [name, maximum] of Object.entries(MAX_SCAN_LIMITS)) {
    assert.equal(config.properties[name].maximum, maximum, `config.${name}`);
    assert.equal(config.properties[name].minimum, minimums[name] ?? 1, `config.${name} minimum`);
    assert.equal(reportLimits[name].maximum, maximum, `report.limits.${name}`);
    assert.equal(reportLimits[name].minimum, minimums[name] ?? 1, `report.limits.${name} minimum`);
  }
  assert.equal(checkpoint.properties.elapsedMs.maximum, MAX_SCAN_LIMITS.maxElapsedMs);
  assert.equal(checkpoint.properties.requestCount.maximum, MAX_SCAN_LIMITS.maxRequests);
  assert.equal(config.properties.authHeaderOrigins.minItems, 1);
  assert.equal(config.properties.authHeaders.additionalProperties.maxLength, 4096);
  assert.ok(config.allOf.some((rule) => rule.if.properties.rendered.const === true && rule.then.properties.confirmRendered.const === true));
  assert.ok(checkpoint.allOf.some((rule) => rule.if.properties.status.const === "complete" && rule.then.required.includes("report")));
});

test("public types declare the source hard limits and report summary", async () => {
  const declarations = await readFile(new URL("index.d.ts", root), "utf8");
  const hardLimits = declarations.match(/export interface ScanHardLimits \{([\s\S]*?)\n\}/)?.[1];
  assert.ok(hardLimits, "ScanHardLimits declaration is present");
  const declaredLimitNames = [...hardLimits.matchAll(/^\s+([A-Za-z][A-Za-z0-9]*): number;/gm)].map((match) => match[1]).sort();
  assert.deepEqual(declaredLimitNames, Object.keys(MAX_SCAN_LIMITS).sort());
  assert.match(declarations, /export declare const MAX_SCAN_LIMITS: Readonly<ScanHardLimits>/);
  assert.match(declarations, /export interface ScanDefaults extends ScanLimits \{\s+confirmRendered: boolean;/);
  for (const field of ["pagesScanned", "resourcesScanned", "requestsMade", "elapsedMs", "termination", "actionableFindings", "suppressedFindings"]) {
    assert.match(declarations, new RegExp(`\\b${field}: (?:number|string);`));
  }
});

test("package metadata exposes the typed entry point", async () => {
  const packageJson = JSON.parse(await readFile(join(new URL("../", import.meta.url).pathname, "package.json"), "utf8"));
  assert.equal(packageJson.types, "./index.d.ts");
  assert.equal(packageJson.exports["."].import, "./src/index.mjs");
});
