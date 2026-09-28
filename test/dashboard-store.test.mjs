import test from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { DashboardStore } from "../src/dashboard-store.mjs";
import { AuditLog } from "../src/audit.mjs";

test("dashboard store atomically persists redacted job state and interrupts active jobs on restart", async () => {
  const directory = await mkdtemp(join(tmpdir(), "sentinelscan-store-"));
  try {
    const store = new DashboardStore(directory);
    await store.save(new Map([["job-1", { id: "job-1", status: "running", createdAt: "2026-01-01T00:00:00Z", progress: { requestsMade: 1 }, requestBody: { authHeaders: { authorization: "secret" } } }]]));
    const restored = await store.load();
    assert.equal(restored[0].status, "interrupted");
    assert.match(restored[0].error, /restarted/);
    const raw = await readFile(join(directory, "jobs.json"), "utf8");
    assert.doesNotMatch(raw, /authorization|secret/);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("audit log keeps only redacted operational fields", async () => {
  const directory = await mkdtemp(join(tmpdir(), "sentinelscan-audit-"));
  try {
    const audit = new AuditLog(directory);
    await audit.record("scan-accepted", { jobId: "job-1", target: "https://example.test/?token=secret", reason: "operator request", rawBody: "secret" });
    const raw = await readFile(join(directory, "audit.jsonl"), "utf8");
    assert.match(raw, /REDACTED/);
    assert.doesNotMatch(raw, /secret/);
    assert.doesNotMatch(raw, /rawBody/);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});
