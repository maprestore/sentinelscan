import { mkdir, readFile, rename, writeFile, chmod } from "node:fs/promises";
import { join } from "node:path";

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

export class DashboardStore {
  constructor(directory = process.env.SENTINEL_DASHBOARD_DATA_DIR || "") {
    this.directory = directory;
    this.path = directory ? join(directory, "jobs.json") : "";
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
    return parsed.jobs.filter((job) => job && typeof job.id === "string").map((job) => {
      if (["queued", "running"].includes(job.status)) return { ...job, status: "interrupted", error: "Dashboard restarted before this job completed.", finishedAt: new Date().toISOString() };
      return job;
    });
  }

  async save(jobs) {
    if (!this.path) return;
    await mkdir(this.directory, { recursive: true, mode: 0o700 });
    const temporaryPath = `${this.path}.${process.pid}.tmp`;
    const values = jobs instanceof Map ? jobs.values() : jobs;
    await writeFile(temporaryPath, `${JSON.stringify({ schemaVersion: 1, savedAt: new Date().toISOString(), jobs: [...values].map((job) => storedJob(job)) }, null, 2)}\n`, { encoding: "utf8", mode: 0o600 });
    await rename(temporaryPath, this.path);
    await chmod(this.path, 0o600);
  }
}
