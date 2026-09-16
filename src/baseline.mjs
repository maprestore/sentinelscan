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

  return {
    baselineTarget: baseline.target,
    baselineFinishedAt: baseline.finishedAt,
    newFindings,
    resolvedFindings,
    unchangedFindings,
    summary: {
      new: newFindings.length,
      resolved: resolvedFindings.length,
      unchanged: unchangedFindings.length,
      status: newFindings.length ? "regressed" : resolvedFindings.length ? "improved" : "unchanged",
    },
  };
}
