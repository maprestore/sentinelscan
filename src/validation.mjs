import { assertInScope, normalizeScope } from "./scope.mjs";
import { getDetector } from "./detector-registry.mjs";
import { normalizeAuthHeaderOrigins, normalizeAuthHeaders, normalizeEmailDomain, normalizeTarget } from "./scanner.mjs";
import { normalizeExitPolicy } from "./exit-policy.mjs";
import { normalizeSuppressions } from "./triage.mjs";
import { verifyIntegrity } from "./provenance.mjs";

const CONFIG_KEYS = new Set([
  "maxPages", "maxRedirects", "maxResponseBytes", "timeoutMs", "delayMs", "maxResources", "maxRequests", "maxElapsedMs",
  "checkInfrastructure", "certificateTransparency", "allowPrivateNetwork", "rendered", "confirmRendered", "emailDomain",
  "dkimSelectors", "authHeaders", "authHeaderOrigins", "suppressions", "exitPolicy",
]);

const CONFIG_LIMITS = Object.freeze({
  maxPages: 500,
  maxRedirects: 10,
  maxResponseBytes: 10_000_000,
  timeoutMs: 60_000,
  delayMs: 60_000,
  maxResources: 1_000,
  maxRequests: 5_000,
  maxElapsedMs: 900_000,
});

const SEVERITIES = new Set(["info", "low", "medium", "high"]);

export class ValidationError extends Error {
  constructor(path, message) {
    super(`${path}: ${message}`);
    this.name = "ValidationError";
    this.code = "INVALID_ARTIFACT";
    this.path = path;
  }
}

function fail(path, message) {
  throw new ValidationError(path, message);
}

function object(value, path) {
  if (!value || typeof value !== "object" || Array.isArray(value)) fail(path, "must be an object");
  return value;
}

function array(value, path) {
  if (!Array.isArray(value)) fail(path, "must be an array");
  return value;
}

function string(value, path) {
  if (typeof value !== "string" || !value.trim()) fail(path, "must be a non-empty string");
  return value;
}

function integer(value, path, minimum = 0, maximum = Number.MAX_SAFE_INTEGER) {
  if (!Number.isInteger(value) || value < minimum || value > maximum) fail(path, `must be an integer from ${minimum} to ${maximum}`);
}

function boolean(value, path) {
  if (typeof value !== "boolean") fail(path, "must be a boolean");
}

function keys(value, allowed, path) {
  for (const key of Object.keys(value)) if (!allowed.has(key)) fail(`${path}.${key}`, "is not a supported property");
}

function timestamp(value, path) {
  string(value, path);
  if (Number.isNaN(Date.parse(value))) fail(path, "must be an ISO-compatible timestamp");
}

function validateScope(value, path = "scope") {
  const scope = object(value, path);
  keys(scope, new Set(["name", "allowedOrigins", "includePaths", "excludePaths", "notes"]), path);
  array(scope.allowedOrigins, `${path}.allowedOrigins`);
  scope.allowedOrigins.forEach((entry, index) => string(entry, `${path}.allowedOrigins[${index}]`));
  for (const field of ["includePaths", "excludePaths", "notes"]) {
    if (scope[field] !== undefined) {
      array(scope[field], `${path}.${field}`);
      scope[field].forEach((entry, index) => string(entry, `${path}.${field}[${index}]`));
    }
  }
  if (scope.name !== undefined) string(scope.name, `${path}.name`);
  try {
    return normalizeScope(scope);
  } catch {
    fail(path, "contains an invalid origin or path rule");
  }
}

function validateSuppressions(value, path = "suppressions") {
  array(value, path);
  value.forEach((entry, index) => {
    object(entry, `${path}[${index}]`);
    keys(entry, new Set(["fingerprint", "reason", "expiresAt", "owner"]), `${path}[${index}]`);
  });
  try {
    return normalizeSuppressions(value);
  } catch {
    fail(path, "contains an invalid suppression");
  }
}

export function validateConfig(value) {
  const config = object(value, "config");
  keys(config, CONFIG_KEYS, "config");
  for (const [name, maximum] of Object.entries(CONFIG_LIMITS)) {
    if (config[name] !== undefined) integer(config[name], `config.${name}`, name === "maxRedirects" || name === "delayMs" ? 0 : 1, maximum);
  }
  for (const name of ["checkInfrastructure", "certificateTransparency", "allowPrivateNetwork", "rendered", "confirmRendered"]) {
    if (config[name] !== undefined) boolean(config[name], `config.${name}`);
  }
  if (config.rendered && config.confirmRendered !== true) fail("config.confirmRendered", "must be true when rendered is enabled");
  if (config.emailDomain !== undefined && typeof config.emailDomain !== "string") fail("config.emailDomain", "must be a hostname string");
  if (config.emailDomain?.trim()) {
    try { normalizeEmailDomain(config.emailDomain); } catch { fail("config.emailDomain", "must be a plain hostname"); }
  }
  if (config.dkimSelectors !== undefined) {
    array(config.dkimSelectors, "config.dkimSelectors");
    config.dkimSelectors.forEach((entry, index) => string(entry, `config.dkimSelectors[${index}]`));
    if (config.dkimSelectors.length > 20 || config.dkimSelectors.some((entry) => !/^[A-Za-z0-9_-]{1,63}$/.test(entry))) fail("config.dkimSelectors", "must contain at most 20 simple selector names");
  }
  if (config.authHeaders !== undefined) {
    object(config.authHeaders, "config.authHeaders");
    for (const [name, value] of Object.entries(config.authHeaders)) if (typeof value !== "string") fail(`config.authHeaders.${name}`, "must be a string");
    try { normalizeAuthHeaders(config.authHeaders); } catch { fail("config.authHeaders", "contains an invalid header"); }
  }
  if (config.authHeaderOrigins !== undefined) {
    array(config.authHeaderOrigins, "config.authHeaderOrigins");
    config.authHeaderOrigins.forEach((entry, index) => string(entry, `config.authHeaderOrigins[${index}]`));
    try { normalizeAuthHeaderOrigins(config.authHeaderOrigins, config.authHeaderOrigins[0]); } catch { fail("config.authHeaderOrigins", "contains an invalid origin"); }
  }
  if (config.suppressions !== undefined) validateSuppressions(config.suppressions, "config.suppressions");
  if (config.exitPolicy !== undefined) {
    object(config.exitPolicy, "config.exitPolicy");
    keys(config.exitPolicy, new Set(["failOnSeverity", "failOnBaseline", "requireBaseline", "failOnIncomplete"]), "config.exitPolicy");
    if (config.exitPolicy.failOnSeverity !== undefined && config.exitPolicy.failOnSeverity !== null && config.exitPolicy.failOnSeverity !== "") {
      if (!SEVERITIES.has(String(config.exitPolicy.failOnSeverity).toLowerCase())) fail("config.exitPolicy.failOnSeverity", "must be info, low, medium, or high");
    }
    try { normalizeExitPolicy(config.exitPolicy); } catch { fail("config.exitPolicy", "contains an invalid exit policy"); }
  }
  return { kind: "config", fields: Object.keys(config), limits: CONFIG_LIMITS };
}

function validateFinding(value, path) {
  object(value, path);
  for (const field of ["id", "severity", "title", "evidence", "location", "remediation", "fingerprint"]) string(value[field], `${path}.${field}`);
  if (!SEVERITIES.has(value.severity)) fail(`${path}.severity`, "must be info, low, medium, or high");
  const detector = getDetector(value.id);
  if (!detector) fail(`${path}.id`, "is not in the detector catalog");
  if (detector.severity !== value.severity) fail(`${path}.severity`, "does not match the detector catalog");
  if (value.triage !== undefined) {
    object(value.triage, `${path}.triage`);
    if (!["open", "suppressed"].includes(value.triage.state)) fail(`${path}.triage.state`, "must be open or suppressed");
  }
}

function validateReport(value) {
  const report = object(value, "report");
  for (const field of ["schemaVersion", "scanner", "target", "scope", "startedAt", "finishedAt", "limits", "summary", "findings", "attackPaths", "risk"]) {
    if (report[field] === undefined) fail(`report.${field}`, "is required");
  }
  if (report.schemaVersion !== 2) fail("report.schemaVersion", "must be 2");
  object(report.scanner, "report.scanner");
  string(report.scanner.name, "report.scanner.name");
  string(report.scanner.version, "report.scanner.version");
  if (!["bounded-passive", "bounded-rendered"].includes(report.scanner.mode)) fail("report.scanner.mode", "must be bounded-passive or bounded-rendered");
  let target;
  try { target = normalizeTarget(report.target).href; } catch { fail("report.target", "must be a clean http(s) URL"); }
  const scope = validateScope(report.scope);
  try { assertInScope(target, scope); } catch { fail("report.scope", "does not contain report.target"); }
  timestamp(report.startedAt, "report.startedAt");
  timestamp(report.finishedAt, "report.finishedAt");
  object(report.limits, "report.limits");
  const summary = object(report.summary, "report.summary");
  for (const field of ["findings", "actionableFindings", "suppressedFindings"]) integer(summary[field], `report.summary.${field}`);
  const findings = array(report.findings, "report.findings");
  findings.forEach((entry, index) => validateFinding(entry, `report.findings[${index}]`));
  if (summary.findings !== findings.length) fail("report.summary.findings", "must equal findings.length");
  if (summary.actionableFindings + summary.suppressedFindings !== findings.length) fail("report.summary", "actionableFindings plus suppressedFindings must equal findings.length");
  array(report.attackPaths, "report.attackPaths");
  object(report.risk, "report.risk");
  const warnings = [];
  if (report.integrity !== undefined) {
    if (!verifyIntegrity(report)) fail("report.integrity", "content hash does not match the report");
  } else warnings.push("Report has no integrity hash.");
  if (report.scanIdentity !== undefined && (report.scanIdentity.algorithm !== "sha256" || typeof report.scanIdentity.value !== "string")) fail("report.scanIdentity", "must contain a sha256 value");
  if (report.coverage !== undefined) {
    object(report.coverage, "report.coverage");
    boolean(report.coverage.complete, "report.coverage.complete");
  }
  return { kind: "report", target, findings: findings.length, actionableFindings: summary.actionableFindings, suppressedFindings: summary.suppressedFindings, integrity: report.integrity ? "verified" : "missing", warnings };
}

function validateCheckpoint(value) {
  const checkpoint = object(value, "checkpoint");
  for (const field of ["schemaVersion", "status", "target", "scope"]) if (checkpoint[field] === undefined) fail(`checkpoint.${field}`, "is required");
  if (checkpoint.schemaVersion !== 2) fail("checkpoint.schemaVersion", "must be 2");
  if (!["in-progress", "complete"].includes(checkpoint.status)) fail("checkpoint.status", "must be in-progress or complete");
  let target;
  try { target = normalizeTarget(checkpoint.target).href; } catch { fail("checkpoint.target", "must be a clean http(s) URL"); }
  const scope = validateScope(checkpoint.scope);
  try { assertInScope(target, scope); } catch { fail("checkpoint.scope", "does not contain checkpoint.target"); }
  for (const field of ["queued", "deferred", "visited", "findings", "pages", "resources", "requestLog", "inventoryPages", "inventoryClientApiEndpoints", "inventorySourceMaps"]) {
    if (checkpoint[field] !== undefined) array(checkpoint[field], `checkpoint.${field}`);
  }
  if (checkpoint.elapsedMs !== undefined) integer(checkpoint.elapsedMs, "checkpoint.elapsedMs");
  if (checkpoint.requestCount !== undefined) integer(checkpoint.requestCount, "checkpoint.requestCount");
  if (checkpoint.status === "complete") {
    if (!checkpoint.report) fail("checkpoint.report", "is required for a complete checkpoint");
    validateReport(checkpoint.report);
  }
  const warnings = [];
  if (checkpoint.integrity !== undefined) {
    if (!verifyIntegrity(checkpoint)) fail("checkpoint.integrity", "content hash does not match the checkpoint");
  } else warnings.push("Checkpoint has no integrity hash.");
  return { kind: "checkpoint", target, status: checkpoint.status, integrity: checkpoint.integrity ? "verified" : "missing", warnings };
}

export function validateArtifact(kind, value) {
  if (kind === "scope") {
    const scope = validateScope(value, "scope");
    return { kind: "scope", allowedOrigins: scope.allowedOrigins.length, includePaths: scope.includePaths.length, excludePaths: scope.excludePaths.length };
  }
  if (kind === "config") return validateConfig(value);
  if (kind === "suppressions") return { kind: "suppressions", entries: validateSuppressions(value).length };
  if (kind === "report") return validateReport(value);
  if (kind === "checkpoint") return validateCheckpoint(value);
  fail("artifact", "type must be scope, config, suppressions, report, or checkpoint");
}
