import { assertInScope, normalizeScope } from "./scope.mjs";
import { getDetector } from "./detector-registry.mjs";
import { MAX_SCAN_LIMITS, normalizeAuthHeaderOrigins, normalizeAuthHeaders, normalizeEmailDomain, normalizeTarget } from "./scanner.mjs";
import { normalizeExitPolicy } from "./exit-policy.mjs";
import { normalizeSuppressions, triageCounts } from "./triage.mjs";
import { verifyIntegrity } from "./provenance.mjs";

const CONFIG_KEYS = new Set([
  "maxPages", "maxRedirects", "maxResponseBytes", "timeoutMs", "delayMs", "maxResources", "maxRequests", "maxElapsedMs",
  "checkInfrastructure", "certificateTransparency", "allowPrivateNetwork", "rendered", "confirmRendered", "emailDomain",
  "dkimSelectors", "authHeaders", "authHeaderOrigins", "suppressions", "exitPolicy",
]);

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
  for (const [name, maximum] of Object.entries(MAX_SCAN_LIMITS)) {
    if (config[name] !== undefined) integer(config[name], `config.${name}`, name === "maxRedirects" || name === "delayMs" ? 0 : 1, maximum);
  }
  for (const name of ["checkInfrastructure", "certificateTransparency", "allowPrivateNetwork", "rendered", "confirmRendered"]) {
    if (config[name] !== undefined) boolean(config[name], `config.${name}`);
  }
  if (config.rendered && config.confirmRendered !== true) fail("config.confirmRendered", "must be true when rendered is enabled");
  if (config.emailDomain !== undefined) {
    if (typeof config.emailDomain !== "string") fail("config.emailDomain", "must be a hostname string");
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
  return { kind: "config", fields: Object.keys(config), limits: MAX_SCAN_LIMITS };
}

function validateFinding(value, path) {
  object(value, path);
  for (const field of ["id", "severity", "title", "evidence", "location", "remediation", "fingerprint", "category", "confidence", "status"]) string(value[field], `${path}.${field}`);
  if (!SEVERITIES.has(value.severity)) fail(`${path}.severity`, "must be info, low, medium, or high");
  const detector = getDetector(value.id);
  if (!detector) fail(`${path}.id`, "is not in the detector catalog");
  if (detector.severity !== value.severity) fail(`${path}.severity`, "does not match the detector catalog");
  if (typeof value.confidenceScore !== "number" || !Number.isFinite(value.confidenceScore) || value.confidenceScore < 0 || value.confidenceScore > 1) fail(`${path}.confidenceScore`, "must be a number from 0 to 1");
  if (!["observed", "candidate"].includes(value.status)) fail(`${path}.status`, "must be observed or candidate");
  timestamp(value.observedAt, `${path}.observedAt`);
  if (value.triage !== undefined) {
    object(value.triage, `${path}.triage`);
    keys(value.triage, new Set(["state", "owner", "reason", "expiresAt", "suppressionExpired"]), `${path}.triage`);
    if (!["open", "suppressed"].includes(value.triage.state)) fail(`${path}.triage.state`, "must be open or suppressed");
    if (value.triage.state === "suppressed") {
      string(value.triage.reason, `${path}.triage.reason`);
      timestamp(value.triage.expiresAt, `${path}.triage.expiresAt`);
    }
    if (value.triage.owner !== undefined) string(value.triage.owner, `${path}.triage.owner`);
    if (value.triage.suppressionExpired !== undefined) boolean(value.triage.suppressionExpired, `${path}.triage.suppressionExpired`);
  }
}

function scopeIdentity(scope) {
  return JSON.stringify({
    allowedOrigins: [...(scope?.allowedOrigins || [])].sort(),
    includePaths: [...(scope?.includePaths || [])].sort(),
    excludePaths: [...(scope?.excludePaths || [])].sort(),
  });
}

function validateReport(value) {
  const report = object(value, "report");
  for (const field of ["schemaVersion", "scanner", "target", "scope", "startedAt", "finishedAt", "limits", "scanIdentity", "coverage", "summary", "pages", "resources", "requests", "infrastructure", "inventory", "findings", "suppressions", "attackPaths", "risk", "notes"]) {
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
  if (target !== report.target) fail("report.target", "must use its normalized URL form");
  timestamp(report.startedAt, "report.startedAt");
  timestamp(report.finishedAt, "report.finishedAt");
  if (Date.parse(report.finishedAt) < Date.parse(report.startedAt)) fail("report.finishedAt", "must not precede report.startedAt");
  const limits = object(report.limits, "report.limits");
  const limitKeys = new Set([...CONFIG_KEYS].filter((key) => key !== "exitPolicy"));
  keys(limits, limitKeys, "report.limits");
  for (const [name, maximum] of Object.entries(MAX_SCAN_LIMITS)) {
    if (limits[name] !== undefined) integer(limits[name], `report.limits.${name}`, name === "maxRedirects" || name === "delayMs" ? 0 : 1, maximum);
  }
  for (const name of ["checkInfrastructure", "certificateTransparency", "allowPrivateNetwork", "rendered"]) {
    if (limits[name] !== undefined) boolean(limits[name], `report.limits.${name}`);
  }
  if (limits.emailDomain !== undefined) {
    if (typeof limits.emailDomain !== "string") fail("report.limits.emailDomain", "must be a hostname string");
    try { normalizeEmailDomain(limits.emailDomain); } catch { fail("report.limits.emailDomain", "must be a plain hostname"); }
  }
  if (limits.authHeaderOrigins !== undefined) {
    array(limits.authHeaderOrigins, "report.limits.authHeaderOrigins");
    try { normalizeAuthHeaderOrigins(limits.authHeaderOrigins, target ? new URL(target).origin : ""); } catch { fail("report.limits.authHeaderOrigins", "contains an invalid origin"); }
  }
  if (limits.dkimSelectors !== undefined && (!Array.isArray(limits.dkimSelectors) || limits.dkimSelectors.length > 20 || limits.dkimSelectors.some((selector) => typeof selector !== "string" || !/^[A-Za-z0-9_-]{1,63}$/.test(selector)))) {
    fail("report.limits.dkimSelectors", "must contain at most 20 simple selector names");
  }
  const identity = object(report.scanIdentity, "report.scanIdentity");
  if (identity.algorithm !== "sha256" || typeof identity.value !== "string" || !/^[a-f0-9]{64}$/.test(identity.value)) fail("report.scanIdentity", "must contain a sha256 value");
  const coverage = object(report.coverage, "report.coverage");
  boolean(coverage.complete, "report.coverage.complete");
  string(coverage.termination, "report.coverage.termination");
  for (const field of ["pages", "resources", "requests", "deferred"]) integer(coverage[field], `report.coverage.${field}`);
  if (coverage.complete !== (coverage.termination === "queue-exhausted")) fail("report.coverage", "complete must match the termination reason");
  const summary = object(report.summary, "report.summary");
  for (const field of ["pagesScanned", "resourcesScanned", "requestsMade", "elapsedMs", "findings", "actionableFindings", "suppressedFindings"]) integer(summary[field], `report.summary.${field}`);
  string(summary.termination, "report.summary.termination");
  const findings = array(report.findings, "report.findings");
  findings.forEach((entry, index) => validateFinding(entry, `report.findings[${index}]`));
  if (summary.findings !== findings.length) fail("report.summary.findings", "must equal findings.length");
  if (summary.actionableFindings + summary.suppressedFindings !== findings.length) fail("report.summary", "actionableFindings plus suppressedFindings must equal findings.length");
  const expectedTriage = triageCounts(findings);
  if (summary.actionableFindings !== expectedTriage.actionableFindings || summary.suppressedFindings !== expectedTriage.suppressedFindings) fail("report.summary", "triage counts must match the findings");
  if (summary.pagesScanned !== coverage.pages || summary.resourcesScanned !== coverage.resources || summary.requestsMade !== coverage.requests) fail("report.summary", "coverage counts must match the summary");
  array(report.pages, "report.pages");
  array(report.resources, "report.resources");
  array(report.requests, "report.requests");
  object(report.infrastructure, "report.infrastructure");
  object(report.inventory, "report.inventory");
  validateSuppressions(report.suppressions, "report.suppressions");
  const paths = array(report.attackPaths, "report.attackPaths");
  paths.forEach((path, index) => {
    const pathLabel = `report.attackPaths[${index}]`;
    object(path, pathLabel);
    for (const field of ["id", "severity", "title", "whyItMatters", "nextAction"]) string(path[field], `${pathLabel}.${field}`);
    if (!SEVERITIES.has(path.severity)) fail(`${pathLabel}.severity`, "must be info, low, medium, or high");
    array(path.findingFingerprints, `${pathLabel}.findingFingerprints`);
    path.findingFingerprints.forEach((fingerprint, position) => string(fingerprint, `${pathLabel}.findingFingerprints[${position}]`));
  });
  const risk = object(report.risk, "report.risk");
  if (typeof risk.score !== "number" || !Number.isFinite(risk.score) || risk.score < 0 || risk.score > 100) fail("report.risk.score", "must be a number from 0 to 100");
  if (!["A", "B", "C", "D", "F"].includes(risk.grade)) fail("report.risk.grade", "must be A, B, C, D, or F");
  string(risk.method, "report.risk.method");
  array(risk.contributions, "report.risk.contributions");
  array(risk.priority, "report.risk.priority");
  array(report.notes, "report.notes");
  report.notes.forEach((note, index) => string(note, `report.notes[${index}]`));
  const warnings = [];
  if (report.integrity !== undefined) {
    if (!verifyIntegrity(report)) fail("report.integrity", "content hash does not match the report");
  } else warnings.push("Report has no integrity hash.");
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
  if (checkpoint.elapsedMs !== undefined) integer(checkpoint.elapsedMs, "checkpoint.elapsedMs", 0, MAX_SCAN_LIMITS.maxElapsedMs);
  if (checkpoint.requestCount !== undefined) integer(checkpoint.requestCount, "checkpoint.requestCount", 0, MAX_SCAN_LIMITS.maxRequests);
  if (checkpoint.wellKnownIndex !== undefined) integer(checkpoint.wellKnownIndex, "checkpoint.wellKnownIndex", 0, 9);
  for (const [field, entries] of [["queued", checkpoint.queued], ["deferred", checkpoint.deferred]]) {
    for (const [index, entry] of (entries || []).entries()) {
      const entryPath = `checkpoint.${field}[${index}]`;
      const urlValue = typeof entry === "string" ? entry : object(entry, entryPath).url;
      if (typeof urlValue !== "string" || !urlValue) fail(entryPath, "must contain a URL");
      let normalized;
      try { normalized = normalizeTarget(urlValue).href; } catch { fail(`${entryPath}.url`, "must be a clean http(s) URL"); }
      try { assertInScope(normalized, scope); } catch { fail(`${entryPath}.url`, "must be inside checkpoint.scope"); }
      if (typeof entry === "object" && entry.kind !== undefined && !["page", "resource", "unknown"].includes(entry.kind)) fail(`${entryPath}.kind`, "is not supported");
    }
  }
  for (const [index, urlValue] of (checkpoint.visited || []).entries()) {
    let normalized;
    try { normalized = normalizeTarget(urlValue).href; } catch { fail(`checkpoint.visited[${index}]`, "must be a clean http(s) URL"); }
    try { assertInScope(normalized, scope); } catch { fail(`checkpoint.visited[${index}]`, "must be inside checkpoint.scope"); }
  }
  (checkpoint.findings || []).forEach((finding, index) => validateFinding(finding, `checkpoint.findings[${index}]`));
  if (checkpoint.status === "complete") {
    if (!checkpoint.report) fail("checkpoint.report", "is required for a complete checkpoint");
    validateReport(checkpoint.report);
    if (checkpoint.report.target !== target || scopeIdentity(checkpoint.report.scope) !== scopeIdentity(scope)) fail("checkpoint.report", "must match the checkpoint target and scope");
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
