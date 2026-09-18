import { createHash } from "node:crypto";

const SEVERITY_RANK = { low: 1, medium: 2, high: 3, critical: 4 };

function highestSeverity(findings) {
  return findings.reduce((highest, finding) => (
    SEVERITY_RANK[finding.severity] > SEVERITY_RANK[highest] ? finding.severity : highest
  ), "low");
}

function assertBaseUrl(value) {
  const url = new URL(value);
  if (!/^https?:$/.test(url.protocol) || url.username || url.password || url.search || url.hash) {
    throw new Error("AegisGrid URL must be a plain HTTP(S) base URL without credentials or query parameters.");
  }
  return url.href.replace(/\/$/, "");
}

export function buildSecurityFindingPayload(report) {
  const findings = Array.isArray(report.findings) ? report.findings : [];
  const target = new URL(report.target);
  const digest = createHash("sha256")
    .update(`${report.target}|${report.generatedAt}|${report.risk?.score ?? 0}`)
    .digest("hex")
    .slice(0, 24);
  const evidence = [
    { type: "risk", title: "SentinelScan risk", value: `${report.risk?.score ?? 0}/100 (${report.risk?.grade ?? "unknown"})` },
    ...findings.slice(0, 39).map((finding) => ({
      type: "finding",
      title: finding.title,
      value: finding.evidence,
    })),
  ];
  return {
    source: "sentinelscan",
    externalEventId: `sentinelscan:${digest}`,
    eventType: "security.finding.created",
    title: `SentinelScan: ${findings.length} finding${findings.length === 1 ? "" : "s"} on ${target.hostname}`,
    summary: `Risk ${report.risk?.score ?? 0}/100 (${report.risk?.grade ?? "unknown"}); ${report.summary?.pagesScanned ?? 0} pages and ${report.summary?.requestsMade ?? 0} requests observed.`,
    severity: highestSeverity(findings),
    confidence: findings.length ? Math.max(...findings.map((finding) => Number(finding.confidenceScore) || 0.5)) : 0,
    occurredAt: report.generatedAt,
    evidence,
    createIncident: findings.length > 0,
    target: report.target,
    findings: findings.slice(0, 100).map((finding) => ({
      id: finding.id,
      severity: finding.severity,
      title: finding.title,
      evidence: finding.evidence,
      location: finding.location,
      remediation: finding.remediation,
      fingerprint: finding.fingerprint,
    })),
  };
}

export async function publishSecurityFinding(report, { baseUrl, tenant, apiKey }) {
  if (!baseUrl || !tenant || !apiKey) throw new Error("AegisGrid publishing requires base URL, tenant, and API key.");
  const url = `${assertBaseUrl(baseUrl)}/api/t/${encodeURIComponent(tenant)}/integrations/security-findings`;
  const response = await fetch(url, {
    method: "POST",
    headers: { "content-type": "application/json", "x-api-key": apiKey },
    body: JSON.stringify(buildSecurityFindingPayload(report)),
    signal: AbortSignal.timeout(10_000),
  });
  const body = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(`AegisGrid rejected SentinelScan finding (${response.status}): ${body.error || "unknown error"}`);
  return body;
}
