import { appendFile, mkdir } from "node:fs/promises";
import { join } from "node:path";
import { redactUrl } from "./scanner.mjs";

export class AuditLog {
  constructor(directory = process.env.SENTINEL_DASHBOARD_DATA_DIR || "") {
    this.path = directory ? join(directory, "audit.jsonl") : "";
    this.events = [];
  }

  async record(type, fields = {}) {
    const event = {
      at: new Date().toISOString(),
      type,
      ...(fields.jobId ? { jobId: String(fields.jobId) } : {}),
      ...(fields.target ? { target: (() => { try { return redactUrl(fields.target); } catch { return "[REDACTED]"; } })() } : {}),
      ...(fields.status ? { status: String(fields.status) } : {}),
      ...(fields.reason ? { reason: String(fields.reason).slice(0, 500) } : {}),
      ...(fields.fingerprint ? { fingerprint: String(fields.fingerprint) } : {}),
      ...(fields.state ? { state: String(fields.state) } : {}),
    };
    this.events.push(event);
    if (!this.path) return event;
    await mkdir(join(this.path, ".."), { recursive: true, mode: 0o700 });
    await appendFile(this.path, `${JSON.stringify(event)}\n`, { encoding: "utf8", mode: 0o600 });
    return event;
  }
}
