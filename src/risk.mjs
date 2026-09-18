const SEVERITY_WEIGHT = { info: 0, low: 6, medium: 18, high: 35 };

export const DEFAULT_ATTACK_PATH_RULES = [
  {
    id: "credential-interception-path",
    requiresAll: ["site-served-over-http", "credential-form-over-http"],
    severity: "high",
    title: "Credentials can travel through an unencrypted path",
    whyItMatters: "The site is served over HTTP and a password form submits over HTTP.",
    nextAction: "Move the entire sign-in flow to HTTPS, redirect HTTP before rendering the form, and then confirm the session cookie policy.",
  },
  {
    id: "source-control-exposure-path",
    requiresAll: ["exposed-git-metadata"],
    severity: "high",
    title: "Public source-control metadata may reveal implementation details",
    whyItMatters: "The public Git metadata endpoint returned a repository reference.",
    nextAction: "Remove repository metadata from the web root and rotate any credentials that may have entered repository history.",
  },
  {
    id: "browser-supply-chain-path",
    requiresAll: ["external-script-without-sri", "missing-content-security-policy"],
    severity: "medium",
    title: "Browser supply-chain controls are weak",
    whyItMatters: "An external script is loaded without integrity metadata and no CSP was observed.",
    nextAction: "Pin trusted third-party assets, add SRI where feasible, and deploy a tested CSP.",
  },
  {
    id: "session-ui-defense-path",
    requiresAll: ["missing-clickjacking-protection", "cookie-missing-samesite"],
    severity: "medium",
    title: "Session-facing browser defenses are incomplete",
    whyItMatters: "The site lacks clickjacking protection and at least one cookie has no explicit SameSite policy.",
    nextAction: "Set a deliberate frame policy and explicit SameSite behavior, then verify embedded and cross-site flows.",
  },
  {
    id: "client-secret-exposure-path",
    requiresAll: ["potential-client-secret", "client-api-endpoint"],
    severity: "high",
    title: "A client-side secret may expose an API trust boundary",
    whyItMatters: "A high-confidence secret-like value was found near a client-visible API endpoint.",
    nextAction: "Revoke the exposed credential, move privileged access server-side, and review API authorization boundaries.",
  },
];

function path(id, severity, title, whyItMatters, nextAction, items) {
  return {
    id,
    severity,
    title,
    whyItMatters,
    nextAction,
    findingFingerprints: items.map((item) => item.fingerprint),
  };
}

export function buildAttackPaths(findings, rules = DEFAULT_ATTACK_PATH_RULES) {
  const ids = new Map(findings.map((item) => [item.id, item]));
  return rules.flatMap((rule) => {
    const required = (rule.requiresAll || []).map((id) => ids.get(id)).filter(Boolean);
    const any = rule.requiresAny?.some((id) => ids.has(id)) ?? true;
    if (required.length !== (rule.requiresAll || []).length || !any) return [];
    const selected = [...required];
    for (const id of rule.requiresAny || []) {
      if (ids.has(id)) selected.push(ids.get(id));
    }
    return [path(rule.id, rule.severity, rule.title, rule.whyItMatters, rule.nextAction, selected)];
  });
}

export function calculateRisk(findings, attackPaths = []) {
  const occurrenceCounts = new Map();
  const contributions = findings.map((item) => {
    const occurrence = occurrenceCounts.get(item.id) || 0;
    occurrenceCounts.set(item.id, occurrence + 1);
    const weight = SEVERITY_WEIGHT[item.severity] || 0;
    const multiplier = occurrence === 0 ? 1 : 1 / (occurrence + 1);
    const confidence = Number.isFinite(item.confidenceScore) ? Math.max(0, Math.min(1, item.confidenceScore)) : 1;
    return { fingerprint: item.fingerprint, id: item.id, severity: item.severity, confidence, points: Math.round(weight * multiplier * confidence * 100) / 100 };
  });
  const rawFindingScore = findings.reduce((total, item) => total + (SEVERITY_WEIGHT[item.severity] || 0), 0);
  const findingScore = Math.round(contributions.reduce((total, item) => total + item.points, 0) * 100) / 100;
  const confidenceDiscount = Math.round((rawFindingScore - findingScore) * 100) / 100;
  const attackPathBonus = attackPaths.reduce((total, item) => total + Math.max(6, Math.round((SEVERITY_WEIGHT[item.severity] || 0) / 6)), 0);
  const score = Math.min(100, Math.round((findingScore + attackPathBonus) * 100) / 100);
  const grade = score >= 70 ? "F" : score >= 40 ? "D" : score >= 20 ? "C" : score > 0 ? "B" : "A";
  const priority = [...findings].sort((left, right) => {
    const severityDelta = (SEVERITY_WEIGHT[right.severity] || 0) - (SEVERITY_WEIGHT[left.severity] || 0);
    return severityDelta || (left.title || left.id).localeCompare(right.title || right.id);
  });
  return {
    score,
    grade,
    method: "transparent-weighted-v2-diminishing-returns",
    factors: { rawFindingScore, findingScore, confidenceDiscount, attackPathBonus },
    contributions,
    priority: priority.map((item) => item.fingerprint),
  };
}
