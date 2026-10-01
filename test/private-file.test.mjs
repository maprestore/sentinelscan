import test from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, readFile, readdir, rm, stat } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { writePrivateFileAtomic } from "../src/private-file.mjs";

test("private atomic writes create missing parents and replace without leaving temp files", async () => {
  const directory = await mkdtemp(join(tmpdir(), "sentinelscan-private-file-"));
  try {
    const path = join(directory, "nested", "report.json");
    await writePrivateFileAtomic(path, "first\n");
    await writePrivateFileAtomic(path, "second\n");

    assert.equal(await readFile(path, "utf8"), "second\n");
    assert.equal((await stat(path)).mode & 0o777, 0o600);
    assert.equal((await stat(join(directory, "nested"))).mode & 0o077, 0);
    assert.deepEqual(await readdir(join(directory, "nested")), ["report.json"]);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});
