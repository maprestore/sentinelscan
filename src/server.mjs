#!/usr/bin/env node
import { createServer } from "node:http";
import { readFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { scan, normalizeTarget } from "./scanner.mjs";
import { normalizeScope } from "./scope.mjs";

const ROOT = dirname(dirname(fileURLToPath(import.meta.url)));
const HOST = process.env.HOST || "127.0.0.1";
const PORT = Number(process.env.PORT || 4173);
const MAX_BODY_BYTES = 16_384;
let scanInProgress = false;

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

async function handleScan(request, response) {
  if (scanInProgress) return json(response, 409, { error: "A scan is already running in this local dashboard." });
  scanInProgress = true;
  try {
    const body = await readJson(request);
    if (body.confirmAuthorized !== true) throw new Error("Refusing to scan without explicit authorization confirmation.");
    const target = normalizeTarget(String(body.target || ""));
    const scope = normalizeScope(body.scope || { name: "dashboard-scope", allowedOrigins: [target.origin] });
    if (!scope.allowedOrigins.includes(target.origin)) throw new Error("The target origin must be listed in the supplied scope.");
    const report = await scan(target.href, {
      scope,
      maxPages: boundedNumber(body.maxPages, 20, 1, 20),
      delayMs: boundedNumber(body.delayMs, 250, 0, 2_000),
      timeoutMs: boundedNumber(body.timeoutMs, 8_000, 1_000, 8_000),
    });
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
      return json(response, 200, { realScan: true, mode: "bounded-passive", targetRequests: "GET only" });
    }
    if (request.method === "POST" && request.url === "/api/scan") return await handleScan(request, response);
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
