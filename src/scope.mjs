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
  assertOriginInScope(url.href, scope);
  const pathnames = decodedPathnames(url);
  if (scope.includePaths?.length && !pathnames.some((pathname) => scope.includePaths.some((path) => pathMatches(pathname, path)))) {
    throw new Error(`Out-of-scope path blocked: ${url.pathname}. Allowed paths: ${scope.includePaths.join(", ")}`);
  }
  if (scope.excludePaths?.some((path) => pathnames.some((pathname) => pathMatches(pathname, path)))) {
    throw new Error(`Excluded path blocked: ${url.pathname}.`);
  }
}

export function assertOriginInScope(value, scope) {
  const url = new URL(value);
  if (!/^https?:$/.test(url.protocol) || url.username || url.password) {
    throw new Error("Only clean http(s) URLs without embedded credentials may be scanned.");
  }
  if (!scope.allowedOrigins.some((pattern) => originMatches(url, pattern))) {
    throw new Error(`Out-of-scope navigation blocked: ${url.origin}. Allowed origins: ${scope.allowedOrigins.join(", ")}`);
  }
}

function normalizeOriginPattern(origin) {
  const value = String(origin).trim();
  const match = value.match(/^(https?):\/\/([^/]+)\/?$/i);
  if (!match || /[@?#]/.test(match[2])) {
    throw new Error(`Scope origin must be a clean http(s) origin or wildcard subdomain: ${origin}`);
  }
  const host = match[2].toLowerCase();
  if (host.startsWith("*.") && (!host.slice(2) || host.slice(2).startsWith(".") || host.slice(2).includes("*"))) {
    throw new Error(`Scope wildcard may only use one leading *.: ${origin}`);
  }
  if (host.includes("*") && !host.startsWith("*.")) {
    throw new Error(`Scope wildcard must be a leading subdomain wildcard: ${origin}`);
  }
  const parsed = new URL(`${match[1].toLowerCase()}://${host.replace(/^\*\./, "placeholder.")}`);
  if (parsed.username || parsed.password || parsed.pathname !== "/" || parsed.search || parsed.hash) {
    throw new Error(`Scope origin must be a clean http(s) origin or wildcard subdomain: ${origin}`);
  }
  return `${parsed.protocol}//${host}`;
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
  const wildcard = /^https?:\/\/\*\./i.test(pattern);
  const expected = new URL(wildcard ? pattern.replace(/^((?:https?):\/\/)\*\./i, "$1placeholder.") : pattern);
  if (url.protocol !== expected.protocol || url.port !== expected.port) return false;
  const host = url.hostname.toLowerCase();
  const patternHost = expected.hostname.toLowerCase();
  if (wildcard) {
    const suffix = patternHost.slice("placeholder.".length);
    return host.endsWith(`.${suffix}`) && host !== suffix;
  }
  return host === patternHost;
}

function decodedPathnames(url) {
  const pathnames = [url.pathname];
  let current = url.pathname;
  let stable = false;
  for (let attempt = 0; attempt < 32; attempt += 1) {
    try {
      const decoded = decodeURIComponent(current);
      if (decoded === current) {
        stable = true;
        break;
      }
      pathnames.push(decoded);
      current = decoded;
    } catch {
      stable = true;
      break;
    }
  }
  if (!stable) throw new Error("Encoded path exceeds the scope decoder safety limit.");
  return [...new Set(pathnames)];
}

function pathMatches(pathname, pattern) {
  if (pattern === "/") return true;
  if (pattern.endsWith("/*")) return pathname.startsWith(pattern.slice(0, -1));
  return pathname === pattern || pathname.startsWith(`${pattern}/`);
}
