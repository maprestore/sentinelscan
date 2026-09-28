#!/usr/bin/env node
import { createServer } from "node:http";
import { randomUUID, timingSafeEqual } from "node:crypto";
import { readFile } from "node:fs/promises";
import { isIP } from "node:net";
import { dirname, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { normalizeAuthHeaderOrigins, normalizeAuthHeaders, normalizeEmailDomain, normalizeTarget, scan } from "./scanner.mjs";
import { assertInScope, normalizeScope } from "./scope.mjs";
import { normalizeSuppressions } from "./triage.mjs";
import { DashboardStore } from "./dashboard-store.mjs";
import { RateLimiter } from "./rate-limit.mjs";
import { AuditLog } from "./audit.mjs";

const ROOT = dirname(dirname(fileURLToPath(import.meta.url)));
const HOST = process.env.HOST || "127.0.0.1";
const PORT = Number(process.env.PORT || 4173);
const MAX_BODY_BYTES = 16_384;
const API_TOKEN = process.env.SENTINEL_API_TOKEN || "";
const DATA_DIR = process.env.SENTINEL_DASHBOARD_DATA_DIR || "";
const ALLOWED_ORIGINS = new Set(String(process.env.SENTINEL_ALLOWED_ORIGINS || "").split(",").map((origin) => origin.trim()).filter(Boolean));
let scanInProgress = false;
const jobs = new Map();
const JOB_RETENTION_MS = 15 * 60 * 1_000;
const MAX_RETAINED_JOBS = 100;
const store = new DashboardStore(DATA_DIR);
const audit = new AuditLog(DATA_DIR);
const rateLimiters = {
  create: new RateLimiter({ windowMs: 60_000, max: 30 }),
  sync: new RateLimiter({ windowMs: 60_000, max: 20 }),
  poll: new RateLimiter({ windowMs: 60_000, max: 120 }),
  mutate: new RateLimiter({ windowMs: 60_000, max: 30 }),
};

function persistJobs() {
  store.save(jobs).catch((error) => process.stderr.write(`SentinelScan dashboard store error: ${error.message}\n`));
}

function auditEvent(type, fields) {
  audit.record(type, fields).catch((error) => process.stderr.write(`SentinelScan audit error: ${error.message}\n`));
}

function send(response, status, body, type) {
  response.writeHead(status, {
    "content-type": type,
    "cache-control": "no-store",
    "x-content-type-options": "nosniff",
  });
  response.end(body);
}

function json(response, status, body) {
  send(response, status, JSON.stringify(body), "application/json; charset=utf-8");
}

function clientKey(request) {
  return request.socket.remoteAddress || "unknown";
}

function enforceRateLimit(request, response, bucket) {
  const result = rateLimiters[bucket].check(`${bucket}:${clientKey(request)}`);
  if (result.allowed) return true;
  response.setHeader("retry-after", String(Math.ceil(result.retryAfterMs / 1_000)));
  json(response, 429, { error: "Rate limit exceeded.", retryAfterMs: result.retryAfterMs });
  return false;
}

/** A problem with the request itself (as opposed to a server fault). Carries the HTTP status to return. */
class RequestError extends Error {
  constructor(status, message) {
    super(message);
    this.name = "RequestError";
    this.status = status;
  }
}

async function readJson(request) {
  if (!/^application\/json(?:\s*;|$)/i.test(String(request.headers["content-type"] || ""))) {
    throw new RequestError(415, "Content-Type must be application/json.");
  }
  let size = 0;
  const chunks = [];
  for await (const chunk of request) {
    size += chunk.length;
    if (size > MAX_BODY_BYTES) throw new RequestError(413, "Request body is too large.");
    chunks.push(chunk);
  }
  let body;
  try {
    body = JSON.parse(Buffer.concat(chunks).toString("utf8"));
  } catch {
    throw new RequestError(400, "Request body must be valid JSON.");
  }
  if (body === null || typeof body !== "object" || Array.isArray(body)) {
    throw new RequestError(400, "Request body must be a JSON object.");
  }
  return body;
}

function errorResponse(response, error) {
  if (error instanceof RequestError) return json(response, error.status, { error: error.message });
  process.stderr.write(`SentinelScan dashboard error: ${error instanceof Error ? error.stack || error.message : String(error)}\n`);
  return json(response, 500, { error: "Server error." });
}

function boundedNumber(value, fallback, min, max) {
  if (value === undefined) return fallback;
  if (typeof value !== "number" || !Number.isInteger(value) || !Number.isFinite(value)) throw new Error("Budget values must be integers.");
  return Math.min(max, Math.max(min, value));
}

function hasActiveJob() {
  return [...jobs.values()].some((job) => job.status === "queued" || job.status === "running");
}

function pruneJobs() {
  const completed = [...jobs.values()]
    .filter((job) => !["queued", "running"].includes(job.status))
    .sort((left, right) => Date.parse(left.finishedAt || left.createdAt) - Date.parse(right.finishedAt || right.createdAt));
  while (jobs.size > MAX_RETAINED_JOBS && completed.length) jobs.delete(completed.shift().id);
  persistJobs();
}

function isLoopbackHost(host) {
  const normalized = String(host).replace(/^\[|\]$/g, "").toLowerCase();
  return normalized === "localhost" || normalized.endsWith(".localhost") || (isIP(normalized) > 0 && (normalized === "127.0.0.1" || normalized === "::1"));
}

function tokensMatch(expected, actual) {
  if (!expected || typeof actual !== "string") return false;
  const left = Buffer.from(expected);
  const right = Buffer.from(actual);
  return left.length === right.length && timingSafeEqual(left, right);
}

function assertMutationAccess(request) {
  const origin = request.headers.origin;
  if (origin) {
    const allowed = ALLOWED_ORIGINS.size ? ALLOWED_ORIGINS : new Set([
      `http://127.0.0.1:${PORT}`,
      `http://localhost:${PORT}`,
      `http://[::1]:${PORT}`,
      `http://${HOST}:${PORT}`,
    ]);
    if (!allowed.has(origin)) throw new RequestError(403, "Cross-origin dashboard requests are not allowed.");
  }
  if (API_TOKEN && !tokensMatch(API_TOKEN, request.headers["x-sentinelscan-token"])) {
    throw new RequestError(401, "A valid dashboard API token is required.");
  }
  if (!isLoopbackHost(HOST) && !API_TOKEN) throw new RequestError(403, "A non-loopback dashboard requires SENTINEL_API_TOKEN.");
}

function buildScanOptions(body, signal, onProgress) {
  try {
    return buildValidatedScanOptions(body, signal, onProgress);
  } catch (error) {
    // Everything this function rejects is a problem with what the caller sent.
    if (error instanceof RequestError) throw error;
    throw new RequestError(400, error instanceof Error ? error.message : "Invalid scan request.");
  }
}

function buildValidatedScanOptions(body, signal, onProgress) {
  if (!body || body.confirmAuthorized !== true) throw new Error("Refusing to scan without explicit authorization confirmation.");
  if (typeof body.target !== "string" || !body.target.trim()) throw new Error("target must be a non-empty URL string.");
  const target = normalizeTarget(body.target);
  const scope = normalizeScope(body.scope || { name: "dashboard-scope", allowedOrigins: [target.origin] });
  assertInScope(target.href, scope);
  for (const name of ["checkInfrastructure", "certificateTransparency", "allowPrivateNetwork", "rendered", "confirmRendered"]) {
    if (body[name] !== undefined && typeof body[name] !== "boolean") throw new Error(`${name} must be a boolean.`);
  }
  if (body.rendered === true && body.confirmRendered !== true) throw new Error("Rendered mode requires confirmRendered: true because target JavaScript will execute.");
  const authHeaderOrigins = body.authHeaderOrigins === undefined ? undefined : normalizeAuthHeaderOrigins(body.authHeaderOrigins, target.origin);
  const emailDomain = normalizeEmailDomain(body.emailDomain);
  const suppressions = normalizeSuppressions(body.suppressions);
  return {
    target: target.href,
    options: {
      scope,
      confirmAuthorized: true,
       maxPages: boundedNumber(body.maxPages, 20, 1, 50),
       maxRedirects: boundedNumber(body.maxRedirects, 5, 0, 10),
       maxResources: boundedNumber(body.maxResources, 40, 1, 100),
       maxRequests: boundedNumber(body.maxRequests, 80, 1, 200),
       maxResponseBytes: boundedNumber(body.maxResponseBytes, 1_000_000, 1, 4_000_000),
      maxElapsedMs: boundedNumber(body.maxElapsedMs, 120_000, 1_000, 600_000),
      delayMs: boundedNumber(body.delayMs, 250, 0, 2_000),
      timeoutMs: boundedNumber(body.timeoutMs, 8_000, 1_000, 8_000),
      checkInfrastructure: body.checkInfrastructure === true || body.certificateTransparency === true,
       certificateTransparency: body.certificateTransparency === true,
       allowPrivateNetwork: body.allowPrivateNetwork === true,
       rendered: body.rendered === true,
       confirmRendered: body.confirmRendered === true,
       suppressions,
      emailDomain,
      authHeaders: body.authHeaders === undefined ? {} : normalizeAuthHeaders(body.authHeaders),
      authHeaderOrigins,
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
  persistJobs();
  auditEvent("scan-accepted", { jobId: id, target: body.target, status: job.status });
  job.promise = Promise.resolve().then(async () => {
    job.status = "running";
    job.startedAt = new Date().toISOString();
    job.progress = { ...job.progress, phase: "started" };
    persistJobs();
    auditEvent("job-started", { jobId: id, target: body.target, status: job.status });
    job.report = await runScan(body, controller.signal, (progress) => { job.progress = progress; });
    job.status = "complete";
    auditEvent("job-completed", { jobId: id, target: body.target, status: job.status });
  }).catch((error) => {
    job.status = error.name === "AbortError" ? "canceled" : "error";
    job.error = error instanceof Error ? error.message : "Scan failed.";
    auditEvent(job.status === "canceled" ? "job-canceled" : "job-failed", { jobId: id, target: body.target, status: job.status, reason: job.error });
  }).finally(() => {
    job.finishedAt = new Date().toISOString();
    persistJobs();
    pruneJobs();
    setTimeout(() => jobs.delete(id), JOB_RETENTION_MS).unref?.();
  });
  return job;
}

async function handleScan(request, response) {
  if (scanInProgress || hasActiveJob()) return json(response, 409, { error: "A scan is already running in this local dashboard." });
  scanInProgress = true;
  try {
    const body = await readJson(request);
    auditEvent("sync-scan-accepted", { target: body.target, status: "running" });
    const report = await runScan(body);
    auditEvent("sync-scan-completed", { target: body.target, status: "complete" });
    return json(response, 200, report);
  } catch (error) {
    auditEvent("sync-scan-failed", { status: "error", reason: error instanceof Error ? error.message : "Scan failed." });
    return errorResponse(response, error);
  } finally {
    scanInProgress = false;
  }
}

const server = createServer(async (request, response) => {
  try {
    if (["POST", "DELETE"].includes(request.method) || (request.method === "GET" && /^\/api\/scans\//.test(request.url || ""))) assertMutationAccess(request);
    if (request.method === "GET" && request.url === "/api/health") {
      return json(response, 200, { realScan: true, mode: "bounded-passive", targetRequests: "GET/HEAD only", version: "0.5.0", activeJobs: [...jobs.values()].filter((job) => job.status === "queued" || job.status === "running").length, persistence: Boolean(DATA_DIR), capabilities: ["multi-origin scopes", "client API inventory", "resumable CLI scans", "progress and cancellation", "private-network policy", "finding triage", "optional DNS/TLS/email/CT metadata", "optional rendered mode"] });
    }
    if (request.method === "POST" && request.url === "/api/scan") {
      if (!enforceRateLimit(request, response, "sync")) return;
      return await handleScan(request, response);
    }
    if (request.method === "POST" && request.url === "/api/scans") {
      if (!enforceRateLimit(request, response, "create")) return;
      if (scanInProgress || hasActiveJob()) return json(response, 409, { error: "A scan is already running in this local dashboard." });
      scanInProgress = true;
      try {
        const body = await readJson(request);
        buildScanOptions(body, new AbortController().signal, () => {});
        const job = startJob(body);
        return json(response, 202, { id: job.id, status: job.status, location: `/api/scans/${job.id}` });
      } finally {
        scanInProgress = false;
      }
    }
    const jobMatch = request.url?.match(/^\/api\/scans\/([a-f0-9-]+)$/i);
    if (jobMatch) {
      if (!enforceRateLimit(request, response, request.method === "GET" ? "poll" : "mutate")) return;
      const job = jobs.get(jobMatch[1]);
      if (!job) return json(response, 404, { error: "Scan job not found or expired." });
      if (request.method === "GET") return json(response, 200, publicJob(job));
      if (request.method === "DELETE") {
        if (job.status === "queued" || job.status === "running") job.controller.abort(new DOMException("Canceled by operator.", "AbortError"));
        auditEvent("job-cancel-requested", { jobId: job.id, status: job.status });
        persistJobs();
        return json(response, 202, publicJob(job));
      }
    }
    if (request.method === "GET" && ["/", "/index.html"].includes(request.url)) {
      const page = await readFile(join(ROOT, "docs", "index.html"), "utf8");
      return send(response, 200, page, "text/html; charset=utf-8");
    }
    return json(response, 404, { error: "Not found." });
  } catch (error) {
    return errorResponse(response, error);
  }
});

let startPromise;
export async function startDashboard() {
  if (startPromise) return startPromise;
  startPromise = store.load().then((records) => {
    for (const record of records) jobs.set(record.id, { ...record, controller: new AbortController() });
    if (records.length) persistJobs();
    return new Promise((resolve, reject) => {
      server.once("error", reject);
      server.listen(PORT, HOST, () => {
        process.stdout.write(`SentinelScan dashboard: http://${HOST}:${PORT}\n`);
        process.stdout.write("Real scans require explicit authorization and use bounded GET/HEAD requests only.\n");
        resolve(server);
      });
    });
  });
  return startPromise;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  startDashboard().catch((error) => {
    process.stderr.write(`SentinelScan dashboard could not start: ${error.message}\n`);
    process.exitCode = 1;
  });
}
