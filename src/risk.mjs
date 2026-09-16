const SEVERITY_WEIGHT = { info: 0, low: 6, medium: 18, high: 35 };

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

export function buildAttackPaths(findings) {
  const ids = new Map(findings.map((item) => [item.id, item]));
  const paths = [];

  if (ids.has("site-served-over-http") && ids.has("credential-form-over-http")) {
    paths.push(path(
      "credential-interception-path",
      "high",
      "Credentials can travel through an unencrypted path",
      "The site is served over HTTP and a password form submits over HTTP.",
      "Move the entire sign-in flow to HTTPS, redirect HTTP before rendering the form, and then confirm the session cookie policy.",
      [ids.get("site-served-over-http"), ids.get("credential-form-over-http")],
    ));
  }

  if (ids.has("exposed-git-metadata")) {
    paths.push(path(
      "source-control-exposure-path",
      "high",
      "Public source-control metadata may reveal implementation details",
      "The public Git metadata endpoint returned a repository reference.",
      "Remove repository metadata from the web root and rotate any credentials that may have entered repository history.",
      [ids.get("exposed-git-metadata")],
    ));
  }

  if (ids.has("external-script-without-sri") && ids.has("missing-content-security-policy")) {
    paths.push(path(
      "browser-supply-chain-path",
      "medium",
      "Browser supply-chain controls are weak",
      "An external script is loaded without integrity metadata and no CSP was observed.",
      "Pin trusted third-party assets, add SRI where feasible, and deploy a tested CSP.",
      [ids.get("external-script-without-sri"), ids.get("missing-content-security-policy")],
    ));
  }

  if (ids.has("missing-clickjacking-protection") && ids.has("cookie-missing-samesite")) {
    paths.push(path(
      "session-ui-defense-path",
      "medium",
      "Session-facing browser defenses are incomplete",
      "The site lacks clickjacking protection and at least one cookie has no explicit SameSite policy.",
      "Set a deliberate frame policy and explicit SameSite behavior, then verify embedded and cross-site flows.",
      [ids.get("missing-clickjacking-protection"), ids.get("cookie-missing-samesite")],
    ));
  }

  return paths;
}

export function calculateRisk(findings, attackPaths = []) {
  const findingScore = findings.reduce((total, item) => total + (SEVERITY_WEIGHT[item.severity] || 0), 0);
  const score = Math.min(100, findingScore + attackPaths.length * 6);
  const grade = score >= 70 ? "F" : score >= 40 ? "D" : score >= 20 ? "C" : score > 0 ? "B" : "A";
  const priority = [...findings].sort((left, right) => {
    const severityDelta = (SEVERITY_WEIGHT[right.severity] || 0) - (SEVERITY_WEIGHT[left.severity] || 0);
    return severityDelta || (left.title || left.id).localeCompare(right.title || right.id);
  });
  return {
    score,
    grade,
    method: "transparent-weighted-v1",
    factors: { findingScore, attackPathBonus: attackPaths.length * 6 },
    priority: priority.map((item) => item.fingerprint),
  };
}
