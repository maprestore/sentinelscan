export function normalizeScope(value) {
  if (!value || !Array.isArray(value.allowedOrigins) || value.allowedOrigins.length === 0) {
    throw new Error("Scope must define at least one allowedOrigins entry.");
  }

  const allowedOrigins = [...new Set(value.allowedOrigins.map((origin) => {
    const url = new URL(origin);
    if (!/^https?:$/.test(url.protocol) || url.pathname !== "/" || url.search || url.hash || url.username || url.password) {
      throw new Error(`Scope origin must be a clean http(s) origin: ${origin}`);
    }
    return url.origin;
  }))];

  return {
    name: String(value.name || "unnamed-scope"),
    allowedOrigins,
    notes: Array.isArray(value.notes) ? value.notes.map(String) : [],
  };
}

export function assertInScope(value, scope) {
  const url = new URL(value);
  if (!scope.allowedOrigins.includes(url.origin)) {
    throw new Error(`Out-of-scope navigation blocked: ${url.origin}. Allowed origins: ${scope.allowedOrigins.join(", ")}`);
  }
}
