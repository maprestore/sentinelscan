import test from "node:test";
import assert from "node:assert/strict";
import { existsSync } from "node:fs";
import { readFile, readdir } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const read = (path) => readFile(join(ROOT, path), "utf8");

async function findingIdsInSource() {
  const scanner = await read("src/scanner.mjs");
  const infrastructure = await read("src/infrastructure.mjs");
  const ids = new Set();
  for (const match of scanner.matchAll(/\bfinding\(\s*["']([a-z0-9-]+)["']/g)) ids.add(match[1]);
  for (const match of scanner.matchAll(/^\s*\["([a-z-]+)",\s*"[A-Za-z-]+",\s*"(?:info|low|medium|high)"\],?$/gm)) ids.add(`missing-${match[1]}`);
  for (const match of infrastructure.matchAll(/\bid:\s*"([a-z0-9-]+)",\s*severity:/g)) ids.add(match[1]);
  return ids;
}

test("every finding ID in the source is documented in docs/DETECTIONS.md", async () => {
  const ids = await findingIdsInSource();
  assert.ok(ids.size > 40, `expected to discover the detector catalog, found ${ids.size}`);
  const catalog = await read("docs/DETECTIONS.md");
  const missing = [...ids].filter((id) => !catalog.includes(`\`${id}\``));
  assert.deepEqual(missing, [], `add these findings to docs/DETECTIONS.md: ${missing.join(", ")}`);
  assert.match(catalog, new RegExp(`\\*\\*${ids.size} finding types\\*\\*`), `docs/DETECTIONS.md should say ${ids.size} finding types`);
  assert.match(await read("README.md"), new RegExp(`${ids.size} finding types`), `README.md should say ${ids.size} finding types`);
});

test("relative links in the documentation point at files that exist", async () => {
  const files = ["README.md", "CONTRIBUTING.md", "SECURITY.md", "CODE_OF_CONDUCT.md", "CHANGELOG.md"];
  for (const name of await readdir(join(ROOT, "docs"))) if (name.endsWith(".md")) files.push(`docs/${name}`);

  const broken = [];
  for (const file of files) {
    const text = await read(file);
    const targets = [
      ...[...text.matchAll(/\]\(([^)\s]+)\)/g)].map((match) => match[1]),
      ...[...text.matchAll(/\bsrc="([^"]+)"/g)].map((match) => match[1]),
    ];
    for (const target of targets) {
      if (/^(?:[a-z]+:|#|\.\.\/\.\.\/)/i.test(target)) continue; // external, in-page, or repo-relative GitHub routes
      const path = target.split("#")[0].split("?")[0];
      if (!path) continue;
      if (!existsSync(resolve(ROOT, dirname(file), path))) broken.push(`${file} -> ${target}`);
    }
  }
  assert.deepEqual(broken, [], `broken relative links:\n${broken.join("\n")}`);
});
