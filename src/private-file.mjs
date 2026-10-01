import { randomUUID } from "node:crypto";
import { mkdir, open, rename, unlink } from "node:fs/promises";
import { dirname } from "node:path";

export async function writePrivateFileAtomic(path, contents) {
  await mkdir(dirname(path), { recursive: true, mode: 0o700 });
  const temporaryPath = `${path}.${process.pid}.${randomUUID()}.tmp`;
  let file;
  try {
    file = await open(temporaryPath, "wx", 0o600);
    await file.chmod(0o600);
    await file.writeFile(contents, { encoding: "utf8" });
    await file.sync();
    await file.close();
    file = undefined;
    await rename(temporaryPath, path);
  } finally {
    await file?.close().catch(() => {});
    await unlink(temporaryPath).catch(() => {});
  }
}
