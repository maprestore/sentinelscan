import { readFile } from "node:fs/promises";
import { normalizeScope } from "./scope.mjs";

export async function loadScope(path) {
  let raw;
  try {
    raw = JSON.parse(await readFile(path, "utf8"));
  } catch (error) {
    throw new Error(`Could not read scope file ${path}: ${error.message}`);
  }
  return normalizeScope(raw);
}
