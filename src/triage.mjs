const MAX_SUPPRESSIONS = 1_000;

export function normalizeSuppressions(value) {
  if (value === undefined) return [];
  if (!Array.isArray(value) || value.length > MAX_SUPPRESSIONS) throw new Error(`suppressions must be an array of at most ${MAX_SUPPRESSIONS} entries.`);
  const seen = new Set();
  return value.map((entry, index) => {
    if (!entry || typeof entry !== "object" || Array.isArray(entry)) throw new Error(`Suppression ${index + 1} must be an object.`);
    const fingerprint = String(entry.fingerprint || "").trim();
    const reason = String(entry.reason || "").trim();
    const expiresAt = String(entry.expiresAt || "").trim();
    if (!fingerprint || fingerprint.length > 128) throw new Error(`Suppression ${index + 1} must contain a fingerprint.`);
    if (!reason || reason.length > 2_000) throw new Error(`Suppression ${index + 1} must contain a reason of 1-2000 characters.`);
    if (!expiresAt || Number.isNaN(Date.parse(expiresAt))) throw new Error(`Suppression ${index + 1} must contain a valid expiresAt timestamp.`);
    if (seen.has(fingerprint)) throw new Error(`Suppression fingerprint is duplicated: ${fingerprint}`);
    seen.add(fingerprint);
    const owner = entry.owner === undefined ? undefined : String(entry.owner).trim();
    if (owner && owner.length > 200) throw new Error(`Suppression ${index + 1} owner is too long.`);
    return { fingerprint, reason, expiresAt: new Date(expiresAt).toISOString(), ...(owner ? { owner } : {}) };
  });
}

export function applyTriage(findings, suppressions = [], now = Date.now()) {
  const byFingerprint = new Map(suppressions.map((entry) => [entry.fingerprint, entry]));
  return findings.map((finding) => {
    const suppression = byFingerprint.get(finding.fingerprint);
    if (!suppression) return { ...finding, triage: { state: "open" } };
    if (Date.parse(suppression.expiresAt) > now) {
      return { ...finding, triage: { state: "suppressed", reason: suppression.reason, expiresAt: suppression.expiresAt, ...(suppression.owner ? { owner: suppression.owner } : {}) } };
    }
    return { ...finding, triage: { state: "open", reason: "Suppression expired and is no longer active.", suppressionExpired: true, expiresAt: suppression.expiresAt, ...(suppression.owner ? { owner: suppression.owner } : {}) } };
  });
}

export function isSuppressed(finding) {
  return finding?.triage?.state === "suppressed";
}

export function actionableFindings(findings = []) {
  return findings.filter((finding) => !isSuppressed(finding));
}

export function triageCounts(findings = []) {
  return {
    actionableFindings: actionableFindings(findings).length,
    suppressedFindings: findings.filter(isSuppressed).length,
  };
}
