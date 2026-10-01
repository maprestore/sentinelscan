import test from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
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

test("dashboard store serializes concurrent saves and keeps the latest snapshot", async () => {
  const directory = await mkdtemp(join(tmpdir(), "sentinelscan-store-race-"));
  try {
    const store = new DashboardStore(directory);
    const saves = Array.from({ length: 32 }, (_, version) => store.save(new Map([
      ["job-1", { id: "job-1", status: "complete", createdAt: new Date().toISOString(), progress: { version } }],
    ])));
    await Promise.all(saves);

    const saved = JSON.parse(await readFile(join(directory, "jobs.json"), "utf8"));
    assert.equal(saved.jobs[0].progress.version, saves.length - 1);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("dashboard store bounds persisted history without discarding active jobs", async () => {
  const directory = await mkdtemp(join(tmpdir(), "sentinelscan-store-retention-"));
  try {
    const store = new DashboardStore(directory);
    const now = Date.now();
    const active = ["queued", "running"].map((status) => ({
      id: status,
      status,
      createdAt: new Date(now - 60_000).toISOString(),
    }));
    const expiredAt = new Date(now - 16 * 60_000).toISOString();
    const expired = { id: "expired", status: "complete", createdAt: expiredAt, finishedAt: expiredAt };
    const recent = Array.from({ length: 102 }, (_, index) => {
      const finishedAt = new Date(now - (102 - index) * 1_000).toISOString();
      return { id: `recent-${index}`, status: "complete", createdAt: finishedAt, finishedAt };
    });
    const records = [...active, expired, ...recent];
    await writeFile(join(directory, "jobs.json"), JSON.stringify({ jobs: records }));

    const restored = await store.load();
    assert.equal(restored.length, 100);
    assert.equal(restored.find((job) => job.id === "queued").status, "interrupted");
    assert.equal(restored.find((job) => job.id === "running").status, "interrupted");
    assert.equal(restored.some((job) => job.id === "expired"), false);
    assert.equal(restored.some((job) => ["recent-0", "recent-1", "recent-2", "recent-3"].includes(job.id)), false);
    assert.equal(restored.some((job) => job.id === "recent-4"), true);

    await store.save(records);
    const saved = JSON.parse(await readFile(join(directory, "jobs.json"), "utf8"));
    assert.equal(saved.jobs.length, 100);
    assert.deepEqual(saved.jobs.filter((job) => ["queued", "running"].includes(job.status)).map((job) => job.id), ["queued", "running"]);
    assert.equal(saved.jobs.some((job) => job.id === "expired"), false);
    assert.equal(saved.jobs.some((job) => job.id === "recent-4"), true);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("audit log keeps only redacted operational fields", async () => {
  const directory = await mkdtemp(join(tmpdir(), "sentinelscan-audit-"));
  try {
    const audit = new AuditLog(directory);
    await audit.record("scan-accepted", {
      jobId: "job-1",
      target: "https://user:password@example.test/?token=target-secret",
      reason: "operator request for https://example.test/?access_token=reason-secret; Authorization: Bearer bearer-secret; api_key=key-secret",
      rawBody: "secret",
    });
    const raw = await readFile(join(directory, "audit.jsonl"), "utf8");
    assert.match(raw, /REDACTED/);
    assert.doesNotMatch(raw, /password|target-secret|reason-secret|bearer-secret|key-secret/);
    assert.doesNotMatch(raw, /rawBody/);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("audit log bounds in-memory event history to the newest events", async () => {
  const audit = new AuditLog();
  await Promise.all(Array.from({ length: 1_050 }, (_, index) => audit.record("job-started", { jobId: `job-${index}` })));
  assert.equal(audit.events.length, 1_000);
  assert.equal(audit.events[0].jobId, "job-50");
  assert.equal(audit.events.at(-1).jobId, "job-1049");
});

test("audit log rotates old lines to keep its private disk file bounded", async () => {
  const directory = await mkdtemp(join(tmpdir(), "sentinelscan-audit-retention-"));
  try {
    const path = join(directory, "audit.jsonl");
    const oldLine = `${JSON.stringify({ type: "old", detail: "x".repeat(4_000) })}\n`;
    const count = Math.ceil((5_000_001 / oldLine.length));
    await writeFile(path, oldLine.repeat(count));

    const audit = new AuditLog(directory);
    await audit.record("new-event", { status: "complete" });
    const raw = await readFile(path, "utf8");
    assert.ok(Buffer.byteLength(raw) <= 5_000_000);
    assert.ok(raw.endsWith("\n"));
    const lines = raw.trimEnd().split("\n").map((line) => JSON.parse(line));
    assert.equal(lines.at(-1).type, "new-event");
    assert.equal(lines.some((line) => line.type === "old"), true);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});
