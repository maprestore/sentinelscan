#!/usr/bin/env node
import { chmod, readFile, rename, writeFile } from "node:fs/promises";
import { scan } from "./scanner.mjs";
import { compareReports } from "./baseline.mjs";
import { loadScope } from "./scope-file.mjs";
import { toSarif } from "./sarif.mjs";
import { toHtml } from "./html.mjs";
import { evaluateExitPolicy, normalizeExitPolicy } from "./exit-policy.mjs";
import { addIntegrity } from "./provenance.mjs";
import { validateArtifact } from "./validation.mjs";

function help() {
  return `SentinelScan 0.5.0

Safe, bounded security-posture checks for targets you own or are explicitly authorized to assess.

Usage:
  node src/cli.mjs --target https://example.com --scope scope.example.json --confirm-authorized
  node src/cli.mjs validate report report.json

Options:
  --target <url>             One http:// or https:// target URL
  --scope <path>             Required JSON scope file containing allowed origins
  --confirm-authorized       Required acknowledgement before any request is sent
  --format <text|json|sarif|html> Output format (default: text)
  --out <path>               Also write the report to a local file
  --config <path>             Load scan defaults from a JSON file
  --max-pages <number>       Same-origin HTML pages to visit (default: 20)
  --max-resources <number>   Same-scope JS/JSON resources to inspect (default: 40)
  --max-requests <number>    Hard cap across page, resource, redirect, and metadata requests (default: 80)
  --max-elapsed-ms <number>  Hard wall-clock cap for one scan (default: 120000)
  --max-response-bytes <n>   Maximum bytes read from one response
  --delay-ms <number>        Delay between requests (default: 250)
  --timeout-ms <number>      Per-request timeout (default: 8000)
  --auth-headers <path>      JSON object of user-supplied session headers
  --auth-header-origins <x>  Comma-separated exact origins allowed to receive those headers (default: target origin)
  --infrastructure           Enable DNS, TLS, SPF, DMARC, DKIM, and CAA checks
  --email-domain <domain>    DNS email-policy domain (defaults to target hostname)
  --certificate-transparency Also query Certificate Transparency for the hostname
  --allow-private-network   Explicitly permit loopback/private targets (local fixtures only)
  --rendered                 Execute target JavaScript in an ephemeral browser context
  --confirm-rendered         Required acknowledgement for rendered mode
  --checkpoint <path>        Write progress so an interrupted scan can resume
  --resume <path>            Resume from a checkpoint JSON file
  --baseline <path>          Compare this run with a previous JSON report
  --suppressions <path>      JSON array of fingerprint suppressions
  --sarif-out <path>         Also write SARIF output while using another primary format
  --fail-on-severity <level> Exit 2 on actionable findings at or above info/low/medium/high
  --fail-on-baseline <mode>  Exit 2 on baseline new/changed/regressed findings
  --require-baseline         Exit 2 when --baseline is not supplied
  --fail-on-incomplete        Exit 2 when the scan stops before its queue is exhausted
  --help                     Show this help

Validation:
  validate <scope|config|suppressions|report|checkpoint> <path> [--json]
  Validate a local artifact without DNS, HTTP, browser, or third-party access.

The scanner uses GET and HEAD requests only. It does not brute-force, exploit, bypass auth,
submit forms, or follow links off the target origin.
`;
}

function parseArgs(argv) {
  const args = {};
  const valueFlags = new Set([
    "target", "scope", "format", "out", "config", "max-pages", "max-resources", "max-requests",
    "max-elapsed-ms", "max-response-bytes", "delay-ms", "timeout-ms", "auth-headers", "auth-header-origins",
    "email-domain", "checkpoint", "resume", "baseline", "suppressions", "sarif-out", "fail-on-severity", "fail-on-baseline",
  ]);
  const booleanFlags = new Set(["help", "confirm-authorized", "infrastructure", "certificate-transparency", "allow-private-network", "rendered", "confirm-rendered", "require-baseline", "fail-on-incomplete"]);
  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index];
    if (!arg.startsWith("--")) throw new Error(`Unknown argument: ${arg}`);
    const [rawKey, ...inlineParts] = arg.slice(2).split("=");
    const key = rawKey;
    if (!booleanFlags.has(key) && !valueFlags.has(key)) throw new Error(`Unknown option --${key}.`);
    if (booleanFlags.has(key)) {
      if (inlineParts.length) throw new Error(`Boolean option --${key} does not accept a value.`);
      args[key] = true;
      continue;
    }
    const inlineValue = inlineParts.length ? inlineParts.join("=") : undefined;
    const value = inlineValue ?? argv[index + 1];
    if (value === undefined || value === "" || (inlineValue === undefined && value.startsWith("--"))) throw new Error(`Missing value for --${key}.`);
    args[key] = value;
    if (inlineValue === undefined) index += 1;
  }
  return args;
}

function validationHelp() {
  return `Usage: node src/cli.mjs validate <scope|config|suppressions|report|checkpoint> <path> [--json]\n\nValidates a local JSON artifact without making network requests.\n`;
}

async function runValidation(argv) {
  if (argv.includes("--help") || argv.length === 0) {
    process.stdout.write(validationHelp());
    return;
  }
  const json = argv.includes("--json");
  const positional = argv.filter((value) => value !== "--json");
  if (positional.length !== 2 || positional.some((value) => value.startsWith("--"))) throw new Error("validate requires exactly one artifact type and one JSON path.");
  const [kind, path] = positional;
  let value;
  try {
    value = JSON.parse(await readFile(path, "utf8"));
  } catch {
    const result = { valid: false, type: kind, file: path, error: { code: "INVALID_JSON", path: "file", message: "Could not read valid JSON from the supplied path." } };
    if (json) process.stdout.write(`${JSON.stringify(result)}\n`);
    else process.stderr.write(`SentinelScan validate: ${result.error.message}\n`);
    process.exitCode = 1;
    return;
  }
  try {
    const summary = validateArtifact(kind, value);
    const result = { valid: true, type: kind, file: path, summary };
    process.stdout.write(`${json ? JSON.stringify(result) : `Valid ${kind}: ${path}`}\n`);
  } catch (error) {
    const result = { valid: false, type: kind, file: path, error: { code: error.code || "INVALID_ARTIFACT", path: error.path || "artifact", message: error.message } };
    if (json) process.stdout.write(`${JSON.stringify(result)}\n`);
    else process.stderr.write(`SentinelScan validate: ${error.message}\n`);
    process.exitCode = 1;
  }
}

function asPositiveInteger(value, flag) {
  const result = Number(value);
  if (!Number.isInteger(result) || result < 1) throw new Error(`${flag} must be a positive integer.`);
  return result;
}

function asNonNegativeInteger(value, flag) {
  const result = Number(value);
  if (!Number.isInteger(result) || result < 0) throw new Error(`${flag} must be a non-negative integer.`);
  return result;
}

function terminalSafe(value) {
  return String(value ?? "")
    .replace(/\u001b(?:\[[0-?]*[ -/]*[@-~]|[@-_])/g, "[ESC]")
    .replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f-\u009f]/g, (character) => `\\x${character.codePointAt(0).toString(16).padStart(2, "0")}`);
}

function renderText(report) {
  const lines = [
    `SentinelScan ${terminalSafe(report.scanner.version)} | ${terminalSafe(report.target)}`,
    `Pages scanned: ${terminalSafe(report.summary.pagesScanned)} | resources=${terminalSafe(report.summary.resourcesScanned)} | requests=${terminalSafe(report.summary.requestsMade)} | stop=${terminalSafe(report.summary.termination)}`,
    `Findings: ${terminalSafe(report.summary.findings)} | actionable=${terminalSafe(report.summary.actionableFindings ?? report.summary.findings)} | suppressed=${terminalSafe(report.summary.suppressedFindings ?? 0)}`,
    `Risk: ${terminalSafe(report.risk.score)}/100 (${terminalSafe(report.risk.grade)}) | attack paths=${terminalSafe(report.attackPaths.length)}`,
    `Coverage: ${terminalSafe(report.coverage?.complete ? "complete" : "incomplete")} | identity=${terminalSafe(report.scanIdentity?.value || "-")}`,
    `Integrity: ${terminalSafe(report.integrity?.contentHash || "-")}`,
    `Inventory: ${terminalSafe(report.inventory.totals.forms)} forms, ${terminalSafe(report.inventory.totals.scripts)} scripts, ${terminalSafe(report.inventory.totals.links)} links, ${terminalSafe(report.inventory.totals.clientApiEndpoints?.length || 0)} client API endpoints`,
    `Severity: ${terminalSafe(Object.entries(report.summary.bySeverity).map(([key, value]) => `${key}=${value}`).join(", ") || "none")}`,
    "",
  ];
  for (const item of report.findings) {
    lines.push(`[${terminalSafe(item.severity.toUpperCase())}] ${terminalSafe(item.title)}`);
    lines.push(`  ${terminalSafe(item.evidence)}`);
    lines.push(`  Location: ${terminalSafe(item.location)}`);
    lines.push(`  Fix: ${terminalSafe(item.remediation)}`);
    lines.push("");
  }
  for (const path of report.attackPaths) {
    lines.push(`[PATH ${terminalSafe(path.severity.toUpperCase())}] ${terminalSafe(path.title)}`);
    lines.push(`  Why it matters: ${terminalSafe(path.whyItMatters)}`);
    lines.push(`  Next action: ${terminalSafe(path.nextAction)}`);
    lines.push("");
  }
  if (report.comparison) {
    const { summary } = report.comparison;
    lines.push(`Baseline: ${terminalSafe(summary.status)} | new=${terminalSafe(summary.new)}, resolved=${terminalSafe(summary.resolved)}, changed=${terminalSafe(summary.changed || 0)}, unchanged=${terminalSafe(summary.unchanged)}, riskDelta=${terminalSafe(summary.riskDelta || 0)}`);
    lines.push("");
  }
  if (report.exitPolicy) lines.push(`Exit policy: ${terminalSafe(report.exitPolicy.failed ? "failed" : "passed")} | ${terminalSafe(report.exitPolicy.reasons.join(" ") || "no policy conditions matched")}`, "");
  lines.push("This is a safe observation report, not proof of exploitability.");
  return lines.join("\n");
}

async function writePrivateOutput(path, output) {
  const temporaryPath = `${path}.${process.pid}.tmp`;
  await writeFile(temporaryPath, `${output}\n`, { encoding: "utf8", mode: 0o600 });
  await rename(temporaryPath, path);
  await chmod(path, 0o600);
}

async function main() {
  const argv = process.argv.slice(2);
  if (argv[0] === "validate") {
    await runValidation(argv.slice(1));
    return;
  }
  const args = parseArgs(argv);
  if (args.help) {
    process.stdout.write(help());
    return;
  }
  if (!args.target) throw new Error("--target is required. Use --help for usage.");
  if (!args.scope) throw new Error("--scope is required. Only origins listed in the scope file may be contacted.");
  if (args["confirm-authorized"] !== true) {
    throw new Error("Refusing to scan without --confirm-authorized. Only scan targets you own or have explicit permission to assess.");
  }
  const format = args.format || "text";
  if (!['text', 'json', 'sarif', 'html'].includes(format)) throw new Error("--format must be text, json, sarif, or html.");

  const scope = await loadScope(args.scope);
  const config = args.config ? JSON.parse(await readFile(args.config, "utf8")) : {};
  if (!config || typeof config !== "object" || Array.isArray(config)) throw new Error("--config must contain a JSON object.");
  const authHeaders = args["auth-headers"] ? JSON.parse(await readFile(args["auth-headers"], "utf8")) : undefined;
  const resume = args.resume ? JSON.parse(await readFile(args.resume, "utf8")) : undefined;
  const suppressions = args.suppressions ? JSON.parse(await readFile(args.suppressions, "utf8")) : undefined;
  const scanOptions = {
    ...config,
    scope,
    confirmAuthorized: true,
    ...(args["max-pages"] ? { maxPages: asPositiveInteger(args["max-pages"], "--max-pages") } : {}),
    ...(args["max-resources"] ? { maxResources: asPositiveInteger(args["max-resources"], "--max-resources") } : {}),
    ...(args["max-requests"] ? { maxRequests: asPositiveInteger(args["max-requests"], "--max-requests") } : {}),
    ...(args["max-elapsed-ms"] ? { maxElapsedMs: asPositiveInteger(args["max-elapsed-ms"], "--max-elapsed-ms") } : {}),
    ...(args["max-response-bytes"] ? { maxResponseBytes: asPositiveInteger(args["max-response-bytes"], "--max-response-bytes") } : {}),
    ...(args["delay-ms"] ? { delayMs: asNonNegativeInteger(args["delay-ms"], "--delay-ms") } : {}),
    ...(args["timeout-ms"] ? { timeoutMs: asPositiveInteger(args["timeout-ms"], "--timeout-ms") } : {}),
    ...(args.infrastructure ? { checkInfrastructure: true } : {}),
    ...(args["email-domain"] ? { emailDomain: args["email-domain"] } : {}),
    ...(args["certificate-transparency"] ? { checkInfrastructure: true, certificateTransparency: true } : {}),
    ...(args["allow-private-network"] ? { allowPrivateNetwork: true } : {}),
    ...(args.rendered ? { rendered: true } : {}),
    ...(args["confirm-rendered"] ? { confirmRendered: true } : {}),
    ...(suppressions === undefined ? {} : { suppressions }),
    ...(authHeaders === undefined ? {} : { authHeaders }),
    ...(args["auth-header-origins"] ? { authHeaderOrigins: args["auth-header-origins"].split(",").map((origin) => origin.trim()).filter(Boolean) } : {}),
    ...(args.checkpoint ? { checkpointPath: args.checkpoint } : {}),
    ...(resume ? { resume } : {}),
  };
  let report = await scan(args.target, scanOptions);
  if (args.baseline) {
    const baseline = JSON.parse(await readFile(args.baseline, "utf8"));
    report.comparison = compareReports(report, baseline);
  }
  const configuredPolicy = config.exitPolicy && typeof config.exitPolicy === "object" ? config.exitPolicy : {};
  const exitPolicy = evaluateExitPolicy(report, normalizeExitPolicy({
    ...configuredPolicy,
    ...(args["fail-on-severity"] === undefined ? {} : { failOnSeverity: args["fail-on-severity"] }),
    ...(args["fail-on-baseline"] === undefined ? {} : { failOnBaseline: args["fail-on-baseline"] }),
    ...(args["require-baseline"] ? { requireBaseline: true } : {}),
    ...(args["fail-on-incomplete"] ? { failOnIncomplete: true } : {}),
  }));
  report = addIntegrity({ ...report, exitPolicy });
  const output = format === "json"
    ? JSON.stringify(report, null, 2)
    : format === "sarif"
      ? JSON.stringify(toSarif(report), null, 2)
      : format === "html"
        ? toHtml(report)
        : renderText(report);
  if (args.out) await writePrivateOutput(args.out, output);
  if (args["sarif-out"]) await writePrivateOutput(args["sarif-out"], JSON.stringify(toSarif(report), null, 2));
  process.stdout.write(`${output}\n`);
  if (exitPolicy.failed) process.exitCode = 2;
}

main().catch((error) => {
  process.stderr.write(`SentinelScan: ${error.message}\n`);
  process.exitCode = 1;
});
