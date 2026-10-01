import { appendFile, chmod, mkdir, open, stat } from "node:fs/promises";
import { dirname, join } from "node:path";
import { redactText, redactUrl } from "./scanner.mjs";
import { writePrivateFileAtomic } from "./private-file.mjs";

const MAX_IN_MEMORY_EVENTS = 1_000;
const MAX_AUDIT_LOG_BYTES = 5_000_000;

function boundedAuditText(value, maxLength) {
  try {
    const text = String(value ?? "")
      .replace(/(\b(?:authorization|proxy-authorization)\b["']?\s*[:=]\s*["']?)(?:bearer|basic)\s+["']?[^\s"',;}]+(["']?)/gi, "$1[REDACTED]$2")
      .replace(/\b(?:bearer|basic)\s+[^\s,;"']+/gi, "[REDACTED]")
      .replace(/(\b(?:cookie|set-cookie)\b["']?\s*[:=]\s*)[^\r\n]*/gi, "$1[REDACTED]");
    return redactText(text).slice(0, maxLength);
  } catch {
    return "[REDACTED]";
  }
}

function redactedTarget(value) {
  try {
    return boundedAuditText(redactUrl(value), 2_048);
  } catch {
    return "[REDACTED]";
  }
}

async function readAuditTail(path, maxBytes) {
  const file = await open(path, "r");
  try {
    const { size } = await file.stat();
    const length = Math.min(size, maxBytes);
    if (!length) return [];
    const buffer = Buffer.alloc(length);
    const { bytesRead } = await file.read(buffer, 0, length, size - length);
    let text = buffer.toString("utf8", 0, bytesRead);
    if (size > length) {
      const firstNewline = text.indexOf("\n");
      text = firstNewline < 0 ? "" : text.slice(firstNewline + 1);
    }
    return text.split("\n").filter(Boolean);
  } finally {
    await file.close();
  }
}

export class AuditLog {
  constructor(directory = process.env.SENTINEL_DASHBOARD_DATA_DIR || "") {
    this.path = directory ? join(directory, "audit.jsonl") : "";
    this.events = [];
    this.writeQueue = Promise.resolve();
  }

  async record(type, fields = {}) {
    const event = {
      at: new Date().toISOString(),
      type: boundedAuditText(type, 100),
      ...(fields.jobId ? { jobId: boundedAuditText(fields.jobId, 100) } : {}),
      ...(fields.target ? { target: redactedTarget(fields.target) } : {}),
      ...(fields.status ? { status: boundedAuditText(fields.status, 80) } : {}),
      ...(fields.reason ? { reason: boundedAuditText(fields.reason, 500) } : {}),
      ...(fields.fingerprint ? { fingerprint: boundedAuditText(fields.fingerprint, 128) } : {}),
      ...(fields.state ? { state: boundedAuditText(fields.state, 80) } : {}),
    };
    if (this.events.length >= MAX_IN_MEMORY_EVENTS) this.events.shift();
    this.events.push(event);
    if (!this.path) return event;
    const line = `${JSON.stringify(event)}\n`;
    const save = this.writeQueue.catch(() => {}).then(async () => {
      await mkdir(dirname(this.path), { recursive: true, mode: 0o700 });
      let existingSize = 0;
      try { existingSize = (await stat(this.path)).size; } catch (error) { if (error.code !== "ENOENT") throw error; }
      if (existingSize + Buffer.byteLength(line) > MAX_AUDIT_LOG_BYTES) {
        const tail = await readAuditTail(this.path, MAX_AUDIT_LOG_BYTES - Buffer.byteLength(line));
        await writePrivateFileAtomic(this.path, tail.length ? `${tail.join("\n")}\n` : "");
      }
      await appendFile(this.path, line, { encoding: "utf8", mode: 0o600 });
      await chmod(this.path, 0o600);
    });
    this.writeQueue = save;
    await save;
    return event;
  }
}
