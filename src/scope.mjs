export function normalizeScope(value) {
  if (!value || !Array.isArray(value.allowedOrigins) || value.allowedOrigins.length === 0) {
    throw new Error("Scope must define at least one allowedOrigins entry.");
  }

  const allowedOrigins = [...new Set(value.allowedOrigins.map(normalizeOriginPattern))];
  const includePaths = normalizePaths(value.includePaths, "includePaths");
  const excludePaths = normalizePaths(value.excludePaths, "excludePaths");

  return {
    name: String(value.name || "unnamed-scope"),
    allowedOrigins,
    includePaths,
    excludePaths,
    notes: Array.isArray(value.notes) ? value.notes.map(String) : [],
  };
}

export function assertInScope(value, scope) {
  const url = new URL(value);
  if (!scope.allowedOrigins.some((pattern) => originMatches(url, pattern))) {
    throw new Error(`Out-of-scope navigation blocked: ${url.origin}. Allowed origins: ${scope.allowedOrigins.join(", ")}`);
  }
  if (scope.includePaths?.length && !scope.includePaths.some((path) => pathMatches(url.pathname, path))) {
    throw new Error(`Out-of-scope path blocked: ${url.pathname}. Allowed paths: ${scope.includePaths.join(", ")}`);
  }
  if (scope.excludePaths?.some((path) => pathMatches(url.pathname, path))) {
    throw new Error(`Excluded path blocked: ${url.pathname}.`);
  }
}

function normalizeOriginPattern(origin) {
  const value = String(origin).trim();
  const match = value.match(/^(https?):\/\/([^/]+)\/?$/i);
  if (!match || /[@?#]/.test(match[2])) {
    throw new Error(`Scope origin must be a clean http(s) origin or wildcard subdomain: ${origin}`);
  }
  const host = match[2].toLowerCase();
  if (host.startsWith("*.") && host.slice(2).includes("*")) {
    throw new Error(`Scope wildcard may only use one leading *.: ${origin}`);
  }
  if (host.includes("*") && !host.startsWith("*.")) {
    throw new Error(`Scope wildcard must be a leading subdomain wildcard: ${origin}`);
  }
  return `${match[1].toLowerCase()}://${host}`;
}

function normalizePaths(paths, field) {
  if (paths === undefined) return [];
  if (!Array.isArray(paths)) throw new Error(`Scope ${field} must be an array when provided.`);
  return [...new Set(paths.map((path) => {
    const value = String(path).trim();
    if (!value.startsWith("/")) throw new Error(`Scope ${field} entries must start with /.`);
    return value === "/" ? value : value.replace(/\/$/, "");
  }))];
}

function originMatches(url, pattern) {
  const expected = new URL(pattern.replace("*.", "placeholder."));
  if (url.protocol !== expected.protocol || url.port !== expected.port) return false;
  const host = url.hostname.toLowerCase();
  const patternHost = expected.hostname.toLowerCase();
  if (patternHost.startsWith("placeholder.")) {
    const suffix = patternHost.slice("placeholder.".length);
    return host.endsWith(`.${suffix}`) && host !== suffix;
  }
  return host === patternHost;
}

function pathMatches(pathname, pattern) {
  if (pattern.endsWith("/*")) return pathname.startsWith(pattern.slice(0, -1));
  return pathname === pattern || pathname.startsWith(`${pattern}/`);
}
