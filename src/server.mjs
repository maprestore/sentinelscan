#!/usr/bin/env node
import { createServer } from "node:http";
import { randomUUID } from "node:crypto";
import { readFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { scan, normalizeAuthHeaders, normalizeTarget } from "./scanner.mjs";
import { assertInScope, normalizeScope } from "./scope.mjs";

const ROOT = dirname(dirname(fileURLToPath(import.meta.url)));
const HOST = process.env.HOST || "127.0.0.1";
const PORT = Number(process.env.PORT || 4173);
const MAX_BODY_BYTES = 16_384;
let scanInProgress = false;
const jobs = new Map();
const JOB_RETENTION_MS = 15 * 60 * 1_000;

function send(response, status, body, type) {
  response.writeHead(status, { "content-type": type, "cache-control": "no-store" });
  response.end(body);
}

function json(response, status, body) {
  send(response, status, JSON.stringify(body), "application/json; charset=utf-8");
}

async function readJson(request) {
  let size = 0;
  const chunks = [];
  for await (const chunk of request) {
    size += chunk.length;
    if (size > MAX_BODY_BYTES) throw new Error("Request body is too large.");
    chunks.push(chunk);
  }
  return JSON.parse(Buffer.concat(chunks).toString("utf8"));
}

function boundedNumber(value, fallback, min, max) {
  const number = Number(value);
  return Number.isFinite(number) ? Math.min(max, Math.max(min, number)) : fallback;
}

function hasActiveJob() {
  return [...jobs.values()].some((job) => job.status === "queued" || job.status === "running");
}

function buildScanOptions(body, signal, onProgress) {
  if (!body || body.confirmAuthorized !== true) throw new Error("Refusing to scan without explicit authorization confirmation.");
  const target = normalizeTarget(String(body.target || ""));
  const scope = normalizeScope(body.scope || { name: "dashboard-scope", allowedOrigins: [target.origin] });
  assertInScope(target.href, scope);
  return {
    target: target.href,
    options: {
      scope,
      maxPages: boundedNumber(body.maxPages, 20, 1, 50),
      maxResources: boundedNumber(body.maxResources, 40, 1, 100),
      maxRequests: boundedNumber(body.maxRequests, 80, 1, 200),
      maxElapsedMs: boundedNumber(body.maxElapsedMs, 120_000, 1_000, 600_000),
      delayMs: boundedNumber(body.delayMs, 250, 0, 2_000),
      timeoutMs: boundedNumber(body.timeoutMs, 8_000, 1_000, 8_000),
      checkInfrastructure: body.checkInfrastructure === true,
      certificateTransparency: body.certificateTransparency === true,
      emailDomain: body.emailDomain ? String(body.emailDomain) : undefined,
      authHeaders: body.authHeaders === undefined ? {} : normalizeAuthHeaders(body.authHeaders),
      authHeaderOrigins: body.authHeaderOrigins,
      signal,
      onProgress,
    },
  };
}

async function runScan(body, signal, onProgress) {
  const { target, options } = buildScanOptions(body, signal, onProgress);
  return scan(target, options);
}

function publicJob(job) {
  return {
    id: job.id,
    status: job.status,
    createdAt: job.createdAt,
    startedAt: job.startedAt || null,
    finishedAt: job.finishedAt || null,
    progress: job.progress,
    error: job.error || null,
    report: job.report || null,
  };
}

function startJob(body) {
  const id = randomUUID();
  const controller = new AbortController();
  const job = {
    id,
    status: "queued",
    createdAt: new Date().toISOString(),
    progress: { phase: "queued", pagesScanned: 0, resourcesScanned: 0, requestsMade: 0 },
    controller,
  };
  jobs.set(id, job);
  job.promise = Promise.resolve().then(async () => {
    job.status = "running";
    job.startedAt = new Date().toISOString();
    job.progress = { ...job.progress, phase: "started" };
    job.report = await runScan(body, controller.signal, (progress) => { job.progress = progress; });
    job.status = "complete";
  }).catch((error) => {
    job.status = error.name === "AbortError" ? "canceled" : "error";
    job.error = error instanceof Error ? error.message : "Scan failed.";
  }).finally(() => {
    job.finishedAt = new Date().toISOString();
    setTimeout(() => jobs.delete(id), JOB_RETENTION_MS).unref?.();
  });
  return job;
}

async function handleScan(request, response) {
  if (scanInProgress || hasActiveJob()) return json(response, 409, { error: "A scan is already running in this local dashboard." });
  scanInProgress = true;
  try {
    const body = await readJson(request);
    const report = await runScan(body);
    return json(response, 200, report);
  } catch (error) {
    return json(response, 400, { error: error instanceof Error ? error.message : "Scan failed." });
  } finally {
    scanInProgress = false;
  }
}

const server = createServer(async (request, response) => {
  try {
    if (request.method === "GET" && request.url === "/api/health") {
      return json(response, 200, { realScan: true, mode: "bounded-passive", targetRequests: "GET only", version: "0.5.0", activeJobs: [...jobs.values()].filter((job) => job.status === "queued" || job.status === "running").length, capabilities: ["multi-origin scopes", "client API inventory", "resumable CLI scans", "progress and cancellation", "optional DNS/TLS/email/CT metadata"] });
    }
    if (request.method === "POST" && request.url === "/api/scan") return await handleScan(request, response);
    if (request.method === "POST" && request.url === "/api/scans") {
      if (scanInProgress || hasActiveJob()) return json(response, 409, { error: "A scan is already running in this local dashboard." });
      const body = await readJson(request);
      buildScanOptions(body, new AbortController().signal, () => {});
      const job = startJob(body);
      return json(response, 202, { id: job.id, status: job.status, location: `/api/scans/${job.id}` });
    }
    const jobMatch = request.url?.match(/^\/api\/scans\/([a-f0-9-]+)$/i);
    if (jobMatch) {
      const job = jobs.get(jobMatch[1]);
      if (!job) return json(response, 404, { error: "Scan job not found or expired." });
      if (request.method === "GET") return json(response, 200, publicJob(job));
      if (request.method === "DELETE") {
        if (job.status === "queued" || job.status === "running") job.controller.abort(new DOMException("Canceled by operator.", "AbortError"));
        return json(response, 202, publicJob(job));
      }
    }
    if (request.method === "GET" && ["/", "/index.html"].includes(request.url)) {
      const page = await readFile(join(ROOT, "docs", "index.html"), "utf8");
      return send(response, 200, page, "text/html; charset=utf-8");
    }
    return json(response, 404, { error: "Not found." });
  } catch (error) {
    return json(response, 500, { error: error instanceof Error ? error.message : "Server error." });
  }
});

server.listen(PORT, HOST, () => {
  process.stdout.write(`SentinelScan dashboard: http://${HOST}:${PORT}\n`);
  process.stdout.write("Real scans require explicit authorization and use bounded GET requests only.\n");
});
