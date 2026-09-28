import { createHash } from "node:crypto";

const LEVELS = { high: "error", medium: "warning", low: "note", info: "note" };

function evidenceFingerprint(item) {
  return createHash("sha256").update(`${item.id}|${item.location}|${item.evidence}`).digest("hex").slice(0, 16);
}

export function toSarif(report, { includeSuppressed = false } = {}) {
  const findings = (report.findings || []).filter((item) => includeSuppressed || item.triage?.state !== "suppressed");
  const rules = [...new Map(findings.map((item) => [item.id, {
    id: item.id,
    name: item.title,
    shortDescription: { text: item.title },
    help: { text: item.remediation },
     properties: { severity: item.severity, confidence: item.confidence, category: item.category, status: item.status },
   }])).values()];
  const results = findings.map((item) => ({
    ruleId: item.id,
    level: LEVELS[item.severity] || "note",
    message: { text: `${item.evidence} Fix: ${item.remediation}` },
    fingerprints: { sentinelscan: item.fingerprint },
    partialFingerprints: {
      sentinelscan: item.fingerprint,
      sentinelscanEvidence: evidenceFingerprint(item),
    },
     locations: [{ physicalLocation: { artifactLocation: { uri: item.location } } }],
     ...(item.triage?.state === "suppressed" ? { suppressions: [{ kind: "external", justification: item.triage.reason || "Suppressed by SentinelScan triage." }] } : {}),
  }));

  return {
    $schema: "https://json.schemastore.org/sarif-2.1.0.json",
    version: "2.1.0",
    runs: [{
      tool: { driver: { name: report.scanner.name, version: report.scanner.version, rules } },
      automationDetails: { id: `sentinelscan/${report.target}` },
      properties: {
        riskScore: report.risk?.score,
        riskGrade: report.risk?.grade,
         attackPaths: report.attackPaths?.length || 0,
          actionableFindings: report.summary?.actionableFindings,
          suppressedFindings: report.summary?.suppressedFindings,
          coverageComplete: report.coverage?.complete,
          scanIdentity: report.scanIdentity?.value,
          reportIntegrity: report.integrity?.contentHash,
          exitPolicyFailed: report.exitPolicy?.failed || false,
      },
      results,
    }],
  };
}
