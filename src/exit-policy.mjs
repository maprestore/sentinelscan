const SEVERITY_RANK = Object.freeze({ info: 0, low: 1, medium: 2, high: 3 });
const BASELINE_MODES = new Set(["never", "new", "changed", "regressed"]);

export function normalizeExitPolicy(value = {}) {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("Exit policy must be an object.");
  const failOnSeverity = value.failOnSeverity === undefined || value.failOnSeverity === null || value.failOnSeverity === "" ? null : String(value.failOnSeverity).toLowerCase();
  if (failOnSeverity !== null && !(failOnSeverity in SEVERITY_RANK)) throw new Error("failOnSeverity must be info, low, medium, or high.");
  const failOnBaseline = String(value.failOnBaseline || "never").toLowerCase();
  if (!BASELINE_MODES.has(failOnBaseline)) throw new Error("failOnBaseline must be never, new, changed, or regressed.");
  if (value.requireBaseline !== undefined && typeof value.requireBaseline !== "boolean") throw new Error("requireBaseline must be a boolean.");
  return { failOnSeverity, failOnBaseline, requireBaseline: value.requireBaseline === true };
}

export function evaluateExitPolicy(report, policy = {}) {
  const normalized = normalizeExitPolicy(policy);
  const actionable = (report?.findings || []).filter((finding) => finding?.triage?.state !== "suppressed");
  const severityMatches = normalized.failOnSeverity === null
    ? []
    : actionable.filter((finding) => (SEVERITY_RANK[finding.severity] ?? -1) >= SEVERITY_RANK[normalized.failOnSeverity]);
  const comparison = report?.comparison;
  const baselineAvailable = Boolean(comparison);
  const baselineReasons = [];
  if (normalized.requireBaseline && !baselineAvailable) baselineReasons.push("A baseline is required but was not supplied.");
  if (baselineAvailable) {
    if (normalized.failOnBaseline === "new" && comparison.summary.new > 0) baselineReasons.push(`${comparison.summary.new} new finding(s) were introduced.`);
    if (normalized.failOnBaseline === "changed" && (comparison.summary.new > 0 || comparison.summary.changed > 0)) baselineReasons.push("The current report differs from the baseline with new or severity-changed findings.");
    if (normalized.failOnBaseline === "regressed" && comparison.summary.status === "regressed") baselineReasons.push("The current report regressed against the baseline.");
  }
  const reasons = [
    ...(severityMatches.length ? [`${severityMatches.length} actionable finding(s) meet the ${normalized.failOnSeverity} severity threshold.`] : []),
    ...baselineReasons,
  ];
  return {
    ...normalized,
    failed: reasons.length > 0,
    reasons,
    matchedFindings: severityMatches.map((finding) => ({ id: finding.id, fingerprint: finding.fingerprint, severity: finding.severity, location: finding.location })),
    baseline: baselineAvailable ? { status: comparison.summary.status, new: comparison.summary.new, changed: comparison.summary.changed, resolved: comparison.summary.resolved } : null,
  };
}

export function severityRank(value) {
  return SEVERITY_RANK[value] ?? 0;
}
