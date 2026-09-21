const fingerprintOf = (item) => item.fingerprint || `${item.id}|${item.location}`;

function groupByFingerprint(report) {
  const groups = new Map();
  for (const item of report?.findings || []) {
    const key = fingerprintOf(item);
    if (!groups.has(key)) groups.set(key, []);
    groups.get(key).push(item);
  }
  return groups;
}

/**
 * Compare two reports finding by finding.
 *
 * A fingerprint identifies an issue on a URL path (finding ID + origin + path),
 * so several distinct instances can legitimately share one fingerprint: for
 * example two cookies that both lack HttpOnly on the same page. Treating the
 * fingerprint as a unique key would silently merge them and hide a regression
 * (a third cookie) or a fix (one of two cookies corrected).
 *
 * Instead, the instances that share a fingerprint are matched as a multiset:
 * first by identical evidence, then in discovery order. Any instance left over on
 * the current side is new; any left over on the baseline side is resolved.
 */
export function compareReports(current, baseline) {
  if (!current?.findings || !baseline?.findings) {
    throw new Error("Both current and baseline reports must contain findings arrays.");
  }
  const currentGroups = groupByFingerprint(current);
  const baselineGroups = groupByFingerprint(baseline);

  const previousFor = new Map(); // current finding -> the baseline finding it matches
  const matchedBaseline = new Set();

  for (const [fingerprint, currentItems] of currentGroups) {
    const available = [...(baselineGroups.get(fingerprint) || [])];
    const unmatched = [];
    for (const item of currentItems) {
      const index = available.findIndex((candidate) => candidate.evidence === item.evidence);
      if (index === -1) {
        unmatched.push(item);
        continue;
      }
      const [previous] = available.splice(index, 1);
      previousFor.set(item, previous);
      matchedBaseline.add(previous);
    }
    for (const item of unmatched) {
      const previous = available.shift();
      if (!previous) continue;
      previousFor.set(item, previous);
      matchedBaseline.add(previous);
    }
  }

  const newFindings = current.findings.filter((item) => !previousFor.has(item));
  const unchangedFindings = current.findings.filter((item) => previousFor.has(item));
  const resolvedFindings = baseline.findings.filter((item) => !matchedBaseline.has(item));
  const changedFindings = unchangedFindings
    .map((item) => ({ previous: previousFor.get(item), current: item }))
    .filter(({ previous, current: item }) => previous.severity !== item.severity);
  const currentScore = Number(current.risk?.score || 0);
  const baselineScore = Number(baseline.risk?.score || 0);

  return {
    baselineTarget: baseline.target,
    baselineFinishedAt: baseline.finishedAt,
    newFindings,
    resolvedFindings,
    unchangedFindings,
    changedFindings,
    summary: {
      new: newFindings.length,
      resolved: resolvedFindings.length,
      unchanged: unchangedFindings.length,
      changed: changedFindings.length,
      riskDelta: currentScore - baselineScore,
      status: newFindings.length || changedFindings.some(({ current: item, previous }) => severityRank(item.severity) > severityRank(previous.severity))
        ? "regressed"
        : resolvedFindings.length || changedFindings.length ? "improved" : "unchanged",
    },
  };
}

function severityRank(value) {
  return { info: 0, low: 1, medium: 2, high: 3 }[value] ?? 0;
}
