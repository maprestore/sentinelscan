#!/usr/bin/env node
import { readFile, writeFile } from "node:fs/promises";
import { scan } from "./scanner.mjs";
import { compareReports } from "./baseline.mjs";
import { loadScope } from "./scope-file.mjs";
import { toSarif } from "./sarif.mjs";
import { toHtml } from "./html.mjs";
import { publishSecurityFinding } from "./aegisgrid.mjs";

function help() {
  return `SentinelScan 0.5.1

Safe, bounded security-posture checks for targets you own or are explicitly authorized to assess.

Usage:
  node src/cli.mjs --target https://example.com --scope scope.example.json --confirm-authorized

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
  --checkpoint <path>        Write progress so an interrupted scan can resume
  --resume <path>            Resume from a checkpoint JSON file
  --baseline <path>          Compare this run with a previous JSON report
  --aegisgrid-url <url>      Publish the completed report to AegisGrid
  --aegisgrid-tenant <slug>  AegisGrid tenant slug
  --aegisgrid-api-key <key>  AegisGrid API key (prefer AEGISGRID_API_KEY)
  --help                     Show this help

The scanner uses GET requests only. It does not brute-force, exploit, bypass auth,
submit forms, or follow links off the target origin.
`;
}

function parseArgs(argv) {
  const args = {};
  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index];
    if (arg === "--help") args.help = true;
    else if (arg === "--confirm-authorized") args.confirmAuthorized = true;
    else if (arg === "--infrastructure") args.infrastructure = true;
    else if (arg === "--certificate-transparency") args.certificateTransparency = true;
    else if (arg.startsWith("--") && arg.includes("=")) {
      const [key, ...rest] = arg.slice(2).split("=");
      args[key] = rest.join("=");
    } else if (arg.startsWith("--")) {
      const key = arg.slice(2);
      const value = argv[index + 1];
      if (!value || value.startsWith("--")) throw new Error(`Missing value for --${key}.`);
      args[key] = value;
      index += 1;
    } else {
      throw new Error(`Unknown argument: ${arg}`);
    }
  }
  return args;
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

function renderText(report) {
  const lines = [
    `SentinelScan ${report.scanner.version} | ${report.target}`,
    `Pages scanned: ${report.summary.pagesScanned} | resources=${report.summary.resourcesScanned} | requests=${report.summary.requestsMade} | stop=${report.summary.termination}`,
    `Findings: ${report.summary.findings}`,
    `Risk: ${report.risk.score}/100 (${report.risk.grade}) | attack paths=${report.attackPaths.length}`,
    `Inventory: ${report.inventory.totals.forms} forms, ${report.inventory.totals.scripts} scripts, ${report.inventory.totals.links} links, ${report.inventory.totals.clientApiEndpoints?.length || 0} client API endpoints`,
    `Severity: ${Object.entries(report.summary.bySeverity).map(([key, value]) => `${key}=${value}`).join(", ") || "none"}`,
    "",
  ];
  for (const item of report.findings) {
    lines.push(`[${item.severity.toUpperCase()}] ${item.title}`);
    lines.push(`  ${item.evidence}`);
    lines.push(`  Location: ${item.location}`);
    lines.push(`  Fix: ${item.remediation}`);
    lines.push("");
  }
  for (const path of report.attackPaths) {
    lines.push(`[PATH ${path.severity.toUpperCase()}] ${path.title}`);
    lines.push(`  Why it matters: ${path.whyItMatters}`);
    lines.push(`  Next action: ${path.nextAction}`);
    lines.push("");
  }
  if (report.comparison) {
    const { summary } = report.comparison;
    lines.push(`Baseline: ${summary.status} | new=${summary.new}, resolved=${summary.resolved}, changed=${summary.changed || 0}, unchanged=${summary.unchanged}, riskDelta=${summary.riskDelta || 0}`);
    lines.push("");
  }
  lines.push("This is a safe observation report, not proof of exploitability.");
  return lines.join("\n");
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  if (args.help) {
    process.stdout.write(help());
    return;
  }
  if (!args.target) throw new Error("--target is required. Use --help for usage.");
  if (!args.scope) throw new Error("--scope is required. Only origins listed in the scope file may be contacted.");
  if (!args.confirmAuthorized) {
    throw new Error("Refusing to scan without --confirm-authorized. Only scan targets you own or have explicit permission to assess.");
  }
  const format = args.format || "text";
  if (!['text', 'json', 'sarif', 'html'].includes(format)) throw new Error("--format must be text, json, sarif, or html.");

  const scope = await loadScope(args.scope);
  const config = args.config ? JSON.parse(await readFile(args.config, "utf8")) : {};
  const authHeaders = args["auth-headers"] ? JSON.parse(await readFile(args["auth-headers"], "utf8")) : undefined;
  const resume = args.resume ? JSON.parse(await readFile(args.resume, "utf8")) : undefined;
  const scanOptions = {
    ...config,
    scope,
    ...(args["max-pages"] ? { maxPages: asPositiveInteger(args["max-pages"], "--max-pages") } : {}),
    ...(args["max-resources"] ? { maxResources: asPositiveInteger(args["max-resources"], "--max-resources") } : {}),
    ...(args["max-requests"] ? { maxRequests: asPositiveInteger(args["max-requests"], "--max-requests") } : {}),
    ...(args["max-elapsed-ms"] ? { maxElapsedMs: asPositiveInteger(args["max-elapsed-ms"], "--max-elapsed-ms") } : {}),
    ...(args["max-response-bytes"] ? { maxResponseBytes: asPositiveInteger(args["max-response-bytes"], "--max-response-bytes") } : {}),
    ...(args["delay-ms"] ? { delayMs: asNonNegativeInteger(args["delay-ms"], "--delay-ms") } : {}),
    ...(args["timeout-ms"] ? { timeoutMs: asPositiveInteger(args["timeout-ms"], "--timeout-ms") } : {}),
    ...(args.infrastructure ? { checkInfrastructure: true } : {}),
    ...(args["email-domain"] ? { emailDomain: args["email-domain"] } : {}),
    ...(args.certificateTransparency ? { checkInfrastructure: true, certificateTransparency: true } : {}),
    ...(authHeaders === undefined ? {} : { authHeaders }),
    ...(args["auth-header-origins"] ? { authHeaderOrigins: args["auth-header-origins"].split(",").map((origin) => origin.trim()).filter(Boolean) } : {}),
    ...(args.checkpoint ? { checkpointPath: args.checkpoint } : {}),
    ...(resume ? { resume } : {}),
  };
  const report = resume?.status === "complete" && resume.report ? resume.report : await scan(args.target, scanOptions);
  if (args.baseline) {
    const baseline = JSON.parse(await readFile(args.baseline, "utf8"));
    report.comparison = compareReports(report, baseline);
  }
  const output = format === "json"
    ? JSON.stringify(report, null, 2)
    : format === "sarif"
      ? JSON.stringify(toSarif(report), null, 2)
      : format === "html"
        ? toHtml(report)
        : renderText(report);
  if (args.out) await writeFile(args.out, `${output}\n`, "utf8");
  const aegisgridValues = [args["aegisgrid-url"], args["aegisgrid-tenant"], args["aegisgrid-api-key"]]
    .concat([process.env.AEGISGRID_URL, process.env.AEGISGRID_TENANT, process.env.AEGISGRID_API_KEY]);
  const hasAegisGridConfig = aegisgridValues.some(Boolean);
  if (hasAegisGridConfig) {
    await publishSecurityFinding(report, {
      baseUrl: args["aegisgrid-url"] || process.env.AEGISGRID_URL,
      tenant: args["aegisgrid-tenant"] || process.env.AEGISGRID_TENANT,
      apiKey: args["aegisgrid-api-key"] || process.env.AEGISGRID_API_KEY,
    });
  }
  process.stdout.write(`${output}\n`);
}

main().catch((error) => {
  process.stderr.write(`SentinelScan: ${error.message}\n`);
  process.exitCode = 1;
});
