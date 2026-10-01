import { mkdir, readFile } from "node:fs/promises";
import { join } from "node:path";
import { writePrivateFileAtomic } from "./private-file.mjs";

const JOB_RETENTION_MS = 15 * 60 * 1_000;
const MAX_RETAINED_JOBS = 100;

function storedJob(job) {
  return {
    id: job.id,
    status: job.status,
    createdAt: job.createdAt,
    startedAt: job.startedAt || null,
    finishedAt: job.finishedAt || null,
    progress: job.progress || null,
    error: job.error || null,
    report: job.report || null,
  };
}

function retainedJobs(jobs, now = Date.now()) {
  const active = [];
  const completed = [];
  for (const job of jobs) {
    if (["queued", "running"].includes(job.status)) {
      active.push(job);
      continue;
    }
    const timestamp = Date.parse(job.finishedAt || job.createdAt || "");
    if (Number.isFinite(timestamp) && now - timestamp > JOB_RETENTION_MS) continue;
    completed.push({ job, timestamp: Number.isFinite(timestamp) ? timestamp : 0 });
  }
  completed.sort((left, right) => left.timestamp - right.timestamp);
  const completedLimit = Math.max(0, MAX_RETAINED_JOBS - active.length);
  const retainedCompleted = completedLimit ? completed.slice(-completedLimit) : [];
  return [...active, ...retainedCompleted.map(({ job }) => job)];
}

export class DashboardStore {
  constructor(directory = process.env.SENTINEL_DASHBOARD_DATA_DIR || "") {
    this.directory = directory;
    this.path = directory ? join(directory, "jobs.json") : "";
    this.saveQueue = Promise.resolve();
  }

  async load() {
    if (!this.path) return [];
    let parsed;
    try {
      parsed = JSON.parse(await readFile(this.path, "utf8"));
    } catch (error) {
      if (error.code === "ENOENT") return [];
      throw new Error(`Dashboard job store could not be read: ${error.message}`);
    }
    if (!Array.isArray(parsed.jobs)) throw new Error("Dashboard job store is invalid.");
    const now = new Date();
    const retained = retainedJobs(parsed.jobs.filter((job) => job && typeof job.id === "string"), now.getTime());
    return retained.map((job) => {
      if (["queued", "running"].includes(job.status)) return { ...job, status: "interrupted", error: "Dashboard restarted before this job completed.", finishedAt: now.toISOString() };
      return job;
    });
  }

  async save(jobs) {
    if (!this.path) return;
    const values = jobs instanceof Map ? jobs.values() : jobs;
    const contents = `${JSON.stringify({ schemaVersion: 1, savedAt: new Date().toISOString(), jobs: retainedJobs([...values].map(storedJob)) }, null, 2)}\n`;
    const save = this.saveQueue.catch(() => {}).then(async () => {
      await mkdir(this.directory, { recursive: true, mode: 0o700 });
      await writePrivateFileAtomic(this.path, contents);
    });
    this.saveQueue = save;
    return save;
  }
}
