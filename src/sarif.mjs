const LEVELS = { high: "error", medium: "warning", low: "note", info: "note" };

export function toSarif(report) {
  const rules = [...new Map(report.findings.map((item) => [item.id, {
    id: item.id,
    name: item.title,
    shortDescription: { text: item.title },
    help: { text: item.remediation },
     properties: { severity: item.severity, confidence: item.confidence, category: item.category, status: item.status },
  }])).values()];
  const results = report.findings.map((item) => ({
    ruleId: item.id,
    level: LEVELS[item.severity] || "note",
    message: { text: `${item.evidence} Fix: ${item.remediation}` },
    fingerprints: { sentinelscan: item.fingerprint },
    locations: [{ physicalLocation: { artifactLocation: { uri: item.location } } }],
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
      },
      results,
    }],
  };
}
