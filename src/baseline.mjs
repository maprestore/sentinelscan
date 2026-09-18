function findingsByFingerprint(report) {
  return new Map((report?.findings || []).map((item) => [
    item.fingerprint || `${item.id}|${item.location}`,
    item,
  ]));
}

export function compareReports(current, baseline) {
  if (!current?.findings || !baseline?.findings) {
    throw new Error("Both current and baseline reports must contain findings arrays.");
  }
  const currentFindings = findingsByFingerprint(current);
  const baselineFindings = findingsByFingerprint(baseline);
  const newFindings = [...currentFindings.entries()]
    .filter(([fingerprint]) => !baselineFindings.has(fingerprint))
    .map(([, item]) => item);
  const resolvedFindings = [...baselineFindings.entries()]
    .filter(([fingerprint]) => !currentFindings.has(fingerprint))
    .map(([, item]) => item);
  const unchangedFindings = [...currentFindings.entries()]
    .filter(([fingerprint]) => baselineFindings.has(fingerprint))
    .map(([, item]) => item);
  const changedFindings = unchangedFindings.map((item) => {
    const previous = baselineFindings.get(item.fingerprint || `${item.id}|${item.location}`);
    return previous?.severity !== item.severity ? { previous, current: item } : null;
  }).filter(Boolean);
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
      status: newFindings.length || changedFindings.some(({ current, previous }) => severityRank(current.severity) > severityRank(previous.severity))
        ? "regressed"
        : resolvedFindings.length || changedFindings.length ? "improved" : "unchanged",
    },
  };
}

function severityRank(value) {
  return { info: 0, low: 1, medium: 2, high: 3 }[value] ?? 0;
}
