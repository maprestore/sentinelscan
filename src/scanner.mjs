import { createHash } from "node:crypto";
import { rename, writeFile } from "node:fs/promises";
import { assertInScope, normalizeScope } from "./scope.mjs";
import { inspectInfrastructure } from "./infrastructure.mjs";
import { buildAttackPaths, calculateRisk, DEFAULT_ATTACK_PATH_RULES } from "./risk.mjs";

const DEFAULTS = {
  maxPages: 20,
  maxRedirects: 5,
  maxResponseBytes: 1_000_000,
  timeoutMs: 8_000,
  delayMs: 250,
  maxResources: 40,
  maxRequests: 80,
  maxElapsedMs: 120_000,
  checkInfrastructure: false,
  certificateTransparency: false,
};

export class ScanBudgetError extends Error {
  constructor(message) {
    super(message);
    this.name = "ScanBudgetError";
    this.code = "SCAN_BUDGET_EXHAUSTED";
  }
}

const SECURITY_HEADERS = [
  ["content-security-policy", "Content-Security-Policy", "low"],
  ["referrer-policy", "Referrer-Policy", "low"],
  ["permissions-policy", "Permissions-Policy", "low"],
];

const DANGEROUS_PATH_WORDS = /(?:admin|private|backup|staging|internal|config|secret|\.env)/i;
const SKIPPED_EXTENSIONS = /\.(?:7z|avi|bin|bmp|css|csv|docx?|gif|gz|ico|jpe?g|m4a|mp3|mp4|pdf|png|svg|tar|tiff?|txt|webm|webp|woff2?|xlsx?|zip)(?:$|\?)/i;
const RESOURCE_EXTENSIONS = /\.(?:js|json|map)(?:$|\?)/i;
const SENSITIVE_QUERY_KEYS = /(?:authorization|api[_-]?key|client[_-]?secret|password|passwd|secret|session|signature|sig|token|access[_-]?token|refresh[_-]?token)/i;
const FINDING_PROFILES = {
  "potential-open-redirect": { category: "redirect", confidence: "low", confidenceScore: 0.45, status: "candidate" },
  "potential-client-secret": { category: "client-exposure", confidence: "medium", confidenceScore: 0.72, status: "candidate" },
  "sensitive-data-in-json": { category: "data-exposure", confidence: "medium", confidenceScore: 0.78, status: "candidate" },
  "client-api-endpoint": { category: "application-inventory", confidence: "high", confidenceScore: 0.98, status: "observed" },
  "public-source-map-reference": { category: "client-exposure", confidence: "high", confidenceScore: 0.96, status: "observed" },
  "client-dangerous-sink": { category: "client-exposure", confidence: "low", confidenceScore: 0.5, status: "candidate" },
  "credential-form-cross-origin": { category: "authentication", confidence: "high", confidenceScore: 0.95, status: "observed" },
  "credential-form-uses-get": { category: "authentication", confidence: "high", confidenceScore: 0.99, status: "observed" },
  "cross-origin-iframe-without-sandbox": { category: "browser-policy", confidence: "high", confidenceScore: 0.95, status: "observed" },
  "sensitive-page-cache-policy": { category: "transport", confidence: "medium", confidenceScore: 0.75, status: "candidate" },
  "request-failed": { category: "availability", confidence: "high", confidenceScore: 0.98, status: "observed" },
  "tls-certificate-invalid": { category: "transport", confidence: "high", confidenceScore: 0.98, status: "observed" },
};

export function normalizeTarget(value) {
  const url = new URL(value);
  if (!/^https?:$/.test(url.protocol)) {
    throw new Error("Target must use http:// or https://.");
  }
  if (url.username || url.password) {
    throw new Error("Targets containing embedded usernames or passwords are not accepted.");
  }
  if ([...url.searchParams.keys()].some((key) => SENSITIVE_QUERY_KEYS.test(key))) {
    throw new Error("Targets containing credential-shaped query parameters are not accepted; use authorized request headers instead.");
  }
  url.hash = "";
  return url;
}

export function redactUrl(value) {
  const url = new URL(value);
  for (const key of url.searchParams.keys()) {
    if (SENSITIVE_QUERY_KEYS.test(key)) url.searchParams.set(key, "[REDACTED]");
  }
  return url.href;
}

function finding(id, severity, title, evidence, location, remediation) {
  const safeLocation = redactUrl(location);
  const url = new URL(safeLocation);
  const fingerprintInput = `${id}|${url.origin}${url.pathname}`;
  const fingerprint = createHash("sha256").update(fingerprintInput).digest("hex").slice(0, 16);
  const profile = FINDING_PROFILES[id] || { category: "security-posture", confidence: "high", confidenceScore: 0.9, status: "observed" };
  return { id, severity, title, evidence, location: safeLocation, remediation, fingerprint, ...profile, observedAt: new Date().toISOString() };
}

function headerValue(headers, name) {
  return headers.get(name)?.trim() || "";
}

export function normalizeAuthHeaders(headers) {
  if (headers === undefined) return {};
  if (!headers || typeof headers !== "object" || Array.isArray(headers)) throw new Error("authHeaders must be an object.");
  const result = {};
  for (const [name, value] of Object.entries(headers)) {
    if (!/^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/.test(name) || /^(?:host|content-length|connection|transfer-encoding)$/i.test(name)) {
      throw new Error(`Unsupported auth header name: ${name}`);
    }
    const normalized = String(value);
    if (normalized.length > 4_096 || /[\r\n]/.test(normalized)) throw new Error(`Invalid auth header value for ${name}.`);
    result[name] = normalized;
  }
  return result;
}

async function readBody(response, maxBytes, signal) {
  if (!response.body) return { text: "", truncated: false };

  const reader = response.body.getReader();
  const chunks = [];
  let total = 0;
  let truncated = false;
  const abortReader = () => reader.cancel(signal.reason);
  signal?.addEventListener("abort", abortReader, { once: true });
  try {
    while (true) {
      if (signal?.aborted) throw signal.reason || new DOMException("The scan was canceled.", "AbortError");
      const { done, value } = await reader.read();
      if (done) break;
      total += value.byteLength;
      if (total > maxBytes) {
        const remaining = maxBytes - (total - value.byteLength);
        if (remaining > 0) chunks.push(value.slice(0, remaining));
        truncated = true;
        await reader.cancel();
        break;
      }
      chunks.push(value);
    }
  } finally {
    signal?.removeEventListener("abort", abortReader);
    reader.releaseLock();
  }

  const bytes = new Uint8Array(chunks.reduce((size, chunk) => size + chunk.byteLength, 0));
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return { text: new TextDecoder().decode(bytes), truncated };
}

async function fetchBounded(startUrl, options, controls = {}) {
  let current = new URL(startUrl);
  const chain = [];
  const requests = [];

  for (let hop = 0; hop <= options.maxRedirects; hop += 1) {
    if (options.signal?.aborted) throw options.signal.reason || new DOMException("The scan was canceled.", "AbortError");
    if (controls.consumeRequest && !controls.consumeRequest()) throw new ScanBudgetError("Maximum request budget reached.");
    assertInScope(current.href, options.scope);
    if ([...current.searchParams.keys()].some((key) => SENSITIVE_QUERY_KEYS.test(key))) throw new Error("Credential-shaped query parameter blocked; use authorized request headers instead.");
    const controller = new AbortController();
    const requestStarted = Date.now();
    const timeout = setTimeout(() => controller.abort(), options.timeoutMs);
    const abortParent = () => controller.abort(options.signal.reason);
    options.signal?.addEventListener("abort", abortParent, { once: true });
    let response;
    try {
      response = await fetch(current, {
        method: "GET",
        redirect: "manual",
        signal: controller.signal,
        headers: {
          accept: "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.1",
          "user-agent": "SentinelScan/0.5 (authorized security posture audit)",
          ...(options.authHeaderOrigins?.includes(current.origin) ? options.authHeaders : {}),
        },
      });
      const status = response.status;
      const location = response.headers.get("location");
      if (status >= 300 && status < 400 && location) {
        const next = new URL(location, current);
        assertInScope(next.href, options.scope);
        requests.push({ url: redactUrl(current.href), status, elapsedMs: Date.now() - requestStarted, redirectedTo: redactUrl(next.href) });
        chain.push({ from: current.href, to: next.href, status });
        current = next;
        continue;
      }

      const body = await readBody(response, options.maxResponseBytes, controller.signal);
      requests.push({ url: redactUrl(current.href), status, elapsedMs: Date.now() - requestStarted, bytesRead: new TextEncoder().encode(body.text).byteLength });
      return {
        requestedUrl: startUrl,
        finalUrl: current.href,
        response,
        body,
        chain,
        requests,
      };
    } finally {
      clearTimeout(timeout);
      options.signal?.removeEventListener("abort", abortParent);
    }
  }

  throw new Error(`Redirect limit exceeded for ${startUrl}`);
}

function addHeaderFindings(findings, headers, url) {
  for (const [key, label, severity] of SECURITY_HEADERS) {
    if (!headerValue(headers, key)) {
      findings.push(finding(
        `missing-${key}`,
        severity,
        `Missing ${label}`,
        `The response from ${url} does not advertise ${label}.`,
        url,
        `Set a policy appropriate for the application and verify it does not break required functionality.`,
      ));
    }
  }

  if (headerValue(headers, "x-content-type-options").toLowerCase() !== "nosniff") {
    findings.push(finding(
      "missing-x-content-type-options",
      "low",
      "MIME sniffing protection is missing",
      "X-Content-Type-Options is absent or is not set to nosniff.",
      url,
      "Send X-Content-Type-Options: nosniff for browser-served resources.",
    ));
  }

  const hsts = headerValue(headers, "strict-transport-security");
  if (hsts) {
    const maxAge = Number(hsts.match(/max-age\s*=\s*(\d+)/i)?.[1] || 0);
    if (maxAge > 0 && maxAge < 15_552_000) {
      findings.push(finding(
        "weak-hsts-duration",
        "low",
        "Strict transport security duration is short",
        `HSTS max-age is ${maxAge} seconds, below the six-month baseline.`,
        url,
        "Use a staged rollout, then target at least six months of HSTS coverage once every required hostname supports HTTPS.",
      ));
    }
    if (!/\bincludeSubDomains\b/i.test(hsts)) {
      findings.push(finding(
        "hsts-missing-subdomains",
        "info",
        "Strict transport security does not cover subdomains",
        "The HSTS response omits includeSubDomains.",
        url,
        "Add includeSubDomains only after confirming every relevant subdomain is HTTPS-ready.",
      ));
    }
  }

  const csp = headerValue(headers, "content-security-policy");
  if (csp) {
    const weakDirectives = csp.match(/(?:^|;)\s*(?:default-src|script-src|style-src)[^;]*(?:'unsafe-inline'|'unsafe-eval'|\*)[^;]*/gi) || [];
    if (weakDirectives.length) {
      findings.push(finding(
        "weak-content-security-policy",
        "medium",
        "Content-Security-Policy contains weak directives",
        weakDirectives.slice(0, 3).join(" | "),
        url,
        "Remove unsafe-inline, unsafe-eval, and broad wildcards where possible; use nonces or hashes for intentional inline code.",
      ));
    }
    if (!/(?:^|;)\s*(?:default-src|script-src)\s+/i.test(csp)) {
      findings.push(finding(
        "incomplete-content-security-policy",
        "low",
        "Content-Security-Policy does not define a default or script policy",
        "The policy has no default-src or script-src directive.",
        url,
        "Define an explicit default-src and script-src policy appropriate for the application.",
      ));
    }
  }

  const hasFrameProtection = Boolean(headerValue(headers, "x-frame-options")) ||
    /frame-ancestors\s+/i.test(headerValue(headers, "content-security-policy"));
  if (!hasFrameProtection) {
    findings.push(finding(
      "missing-clickjacking-protection",
      "medium",
      "Clickjacking protection is missing",
      "Neither X-Frame-Options nor a CSP frame-ancestors directive was observed.",
      url,
      "Set a deliberate frame policy, such as frame-ancestors 'none' or a trusted embedding origin.",
    ));
  }

  if (/^allow-from\b/i.test(headerValue(headers, "x-frame-options"))) {
    findings.push(finding(
      "obsolete-frame-policy",
      "low",
      "X-Frame-Options uses an obsolete directive",
      "X-Frame-Options uses ALLOW-FROM, which modern browsers do not consistently enforce.",
      url,
      "Use CSP frame-ancestors for a modern, testable framing policy.",
    ));
  }

  if (/(?:\/login|\/signin|\/account|\/admin|\/checkout)/i.test(new URL(url).pathname) && !/(?:no-store|no-cache)/i.test(headerValue(headers, "cache-control"))) {
    findings.push(finding(
      "sensitive-page-cache-policy",
      "low",
      "Sensitive-looking page lacks a restrictive cache policy",
      "The URL looks session-facing but Cache-Control does not advertise no-store or no-cache.",
      url,
      "Set a deliberate cache policy for authenticated or sensitive pages and verify intermediary behavior.",
    ));
  }

  if (headerValue(headers, "server") || headerValue(headers, "x-powered-by")) {
    const values = [headerValue(headers, "server"), headerValue(headers, "x-powered-by")].filter(Boolean).join("; ");
    findings.push(finding(
      "technology-disclosure",
      "info",
      "Server technology is disclosed",
      `The response exposes: ${values}.`,
      url,
      "Remove or generalize unnecessary version and framework identifiers where practical.",
    ));
  }

  if (headerValue(headers, "access-control-allow-origin") === "*" && /true/i.test(headerValue(headers, "access-control-allow-credentials"))) {
    findings.push(finding(
      "cors-wildcard-with-credentials",
      "high",
      "CORS allows credentials with a wildcard origin",
      "Access-Control-Allow-Origin is * while Access-Control-Allow-Credentials is true.",
      url,
      "Allow only explicit trusted origins and review whether credentialed cross-origin access is required.",
    ));
  }
}

function getSetCookies(headers) {
  if (typeof headers.getSetCookie === "function") return headers.getSetCookie();
  const combined = headers.get("set-cookie");
  return combined ? [combined] : [];
}

function addCookieFindings(findings, headers, url) {
  for (const cookie of getSetCookies(headers)) {
    const name = cookie.split("=", 1)[0].trim() || "unnamed cookie";
    const lower = cookie.toLowerCase();
    if (new URL(url).protocol === "https:" && !/(^|;)\s*secure(?:;|$)/i.test(cookie)) {
      findings.push(finding(
        "cookie-missing-secure",
        "low",
        "Cookie is missing Secure",
        `${name} is set without the Secure attribute.`,
        url,
        "Add Secure to cookies that should only travel over HTTPS.",
      ));
    }
    if (!/(^|;)\s*httponly(?:;|$)/i.test(cookie)) {
      findings.push(finding(
        "cookie-missing-httponly",
        "low",
        "Cookie is missing HttpOnly",
        `${name} is set without the HttpOnly attribute.`,
        url,
        "Add HttpOnly to cookies that do not need JavaScript access.",
      ));
    }
    if (!/(^|;)\s*samesite=/i.test(lower)) {
      findings.push(finding(
        "cookie-missing-samesite",
        "low",
        "Cookie is missing SameSite",
        `${name} is set without an explicit SameSite attribute.`,
        url,
        "Set SameSite=Lax or SameSite=Strict unless a cross-site use case is intentional.",
      ));
    }
  }
}

function extractAttributeTags(html, tagName) {
  return [...html.matchAll(new RegExp(`<${tagName}\\b[^>]*>`, "gi"))].map((match) => match[0]);
}

function attribute(tag, name) {
  const match = tag.match(new RegExp(`\\b${name}\\s*=\\s*["']([^"']*)["']`, "i"));
  return match?.[1]?.trim() || "";
}

function extractLinks(html, baseUrl) {
  const links = [];
  for (const tag of extractAttributeTags(html, "a")) {
    const href = attribute(tag, "href");
    if (!href || /^(?:#|javascript:|mailto:|tel:|data:)/i.test(href)) continue;
    try {
      const url = new URL(href, baseUrl);
      url.hash = "";
      if (url.protocol === "http:" || url.protocol === "https:") links.push(url);
    } catch {
      // Ignore malformed links in page content.
    }
  }
  return links;
}

function addHtmlFindings(findings, html, pageUrl, rootOrigin) {
  if (!html) return;

  const insecureUrls = [];
  for (const tag of [...extractAttributeTags(html, "script"), ...extractAttributeTags(html, "img"), ...extractAttributeTags(html, "iframe"), ...extractAttributeTags(html, "link")]) {
    for (const attr of ["src", "href"]) {
      const value = attribute(tag, attr);
      if (/^http:\/\//i.test(value)) insecureUrls.push(value);
    }
  }
  if (new URL(pageUrl).protocol === "https:" && insecureUrls.length) {
    findings.push(finding(
      "mixed-content-reference",
      "medium",
      "HTTPS page references HTTP content",
      `${insecureUrls.length} resource reference(s) use http:// on an HTTPS page.`,
      pageUrl,
      "Serve every page resource over HTTPS or remove the dependency.",
    ));
  }

  for (const form of extractAttributeTags(html, "form")) {
    const formAction = attribute(form, "action");
    let formUrl;
    try {
      formUrl = formAction ? new URL(formAction, pageUrl) : new URL(pageUrl);
    } catch {
      continue;
    }
    const formHtml = html.slice(Math.max(0, html.indexOf(form)), Math.min(html.length, html.indexOf(form) + 10_000));
    const hasPassword = /type\s*=\s*["']?password\b/i.test(formHtml);
    if (hasPassword && formUrl.protocol === "http:") {
      findings.push(finding(
        "credential-form-over-http",
        "high",
        "Credential form submits over HTTP",
        "A form containing a password field submits to an HTTP URL.",
        pageUrl,
        "Submit credentials only to an HTTPS endpoint and redirect HTTP traffic before the form is shown.",
      ));
    }
    if (hasPassword && formUrl.origin !== new URL(pageUrl).origin) {
      findings.push(finding(
        "credential-form-cross-origin",
        "high",
        "Credential form submits to another origin",
        `A password form submits to ${formUrl.origin}.`,
        pageUrl,
        "Confirm the destination is an explicitly trusted authentication boundary and that its scope, transport, cookies, and CSRF protections are reviewed together.",
      ));
    }
    if (hasPassword && /method\s*=\s*["']?get\b/i.test(formHtml)) {
      findings.push(finding(
        "credential-form-uses-get",
        "high",
        "Credential form uses GET",
        "A password form declares method=GET, which can place credentials in URLs, logs, and history.",
        pageUrl,
        "Use POST over HTTPS for credential submission and confirm credentials are not accepted in query strings.",
      ));
    }
  }

  for (const iframe of extractAttributeTags(html, "iframe")) {
    const source = attribute(iframe, "src");
    if (!source) continue;
    try {
      const frameUrl = new URL(source, pageUrl);
      if (frameUrl.origin !== new URL(pageUrl).origin && !attribute(iframe, "sandbox")) {
        findings.push(finding(
          "cross-origin-iframe-without-sandbox",
          "low",
          "Cross-origin iframe has no sandbox attribute",
          `${frameUrl.origin} is embedded without sandbox restrictions.`,
          pageUrl,
          "Add the narrowest sandbox policy compatible with the integration and explicitly review postMessage trust.",
        ));
      }
    } catch {
      // Ignore malformed frame URLs.
    }
  }

  for (const anchor of extractAttributeTags(html, "a")) {
    if (attribute(anchor, "target").toLowerCase() !== "_blank") continue;
    if (!/\bnoopener\b/i.test(attribute(anchor, "rel"))) {
      findings.push(finding(
        "external-window-missing-noopener",
        "low",
        "New window link lacks rel=noopener",
        "A link opens a new browsing context without an explicit noopener relationship.",
        pageUrl,
        "Add rel=noopener, and add noreferrer only when the referrer behavior is intentionally changed.",
      ));
    }
  }

  for (const script of extractAttributeTags(html, "script")) {
    const source = attribute(script, "src");
    if (!source) continue;
    try {
      const scriptUrl = new URL(source, pageUrl);
      const external = scriptUrl.origin !== rootOrigin;
      if (external && !attribute(script, "integrity")) {
        findings.push(finding(
          "external-script-without-sri",
          "low",
          "External script has no integrity attribute",
          `${scriptUrl.origin} is loaded without Subresource Integrity metadata.`,
          pageUrl,
          "Pin the script to a trusted version and add an integrity hash with an appropriate crossorigin value.",
        ));
      }
    } catch {
      // Ignore malformed script URLs.
    }
  }
}

function extractPageInventory(html, pageUrl, rootOrigin) {
  const links = extractLinks(html, pageUrl);
  const forms = extractAttributeTags(html, "form");
  const formBlocks = [...html.matchAll(/<form\b[\s\S]*?<\/form>/gi)].map((match) => match[0]);
  const scripts = extractAttributeTags(html, "script");
  const externalScripts = scripts.filter((tag) => {
    const source = attribute(tag, "src");
    if (!source) return false;
    try {
      return new URL(source, pageUrl).origin !== rootOrigin;
    } catch {
      return false;
    }
  });
  const client = extractClientInventory(html, pageUrl);
  return {
    url: pageUrl,
    path: new URL(pageUrl).pathname,
    links: links.length,
    sameOriginLinks: links.filter((link) => link.origin === rootOrigin).length,
    forms: forms.length,
    passwordForms: formBlocks.filter((form) => /type\s*=\s*["']?password\b/i.test(form)).length,
    scripts: scripts.length,
    inlineScripts: scripts.filter((tag) => !attribute(tag, "src")).length,
    externalScripts: externalScripts.length,
    jsonScripts: scripts.filter((tag) => /application\/json/i.test(attribute(tag, "type"))).length,
    clientApiEndpoints: client.endpoints,
    sourceMaps: client.sourceMaps,
  };
}

function normalizeClientEndpoint(value, pageUrl) {
  const raw = String(value).trim().replace(/[),.;]+$/, "");
  if (!raw || /^(?:javascript:|data:|mailto:)/i.test(raw)) return null;
  try {
    const url = new URL(raw, pageUrl);
    if (!/^https?:$/.test(url.protocol)) return null;
    url.hash = "";
    return redactUrl(url.href);
  } catch {
    return null;
  }
}

function extractClientInventory(text, pageUrl) {
  const endpoints = new Set();
  const endpointPattern = /(?:fetch|axios(?:\.[a-z]+)?|XMLHttpRequest|\.open)\s*\([^)]{0,160}?["'`]([^"'`\s]{1,300})["'`]|["'`]((?:\/|https?:\/\/)[^"'`\s<>]{1,300})["'`]/gi;
  for (const match of text.matchAll(endpointPattern)) {
    const candidate = normalizeClientEndpoint(match[1] || match[2], pageUrl);
    if (candidate && (/\/api(?:\/|[?#]|$)/i.test(candidate) || /(?:graphql|oauth|token|webhook|upload|search)/i.test(candidate))) endpoints.add(candidate);
  }
  const sourceMaps = [...text.matchAll(/sourceMappingURL\s*=\s*([^\s*]+)/gi)].map((match) => match[1].trim());
  const secretMatches = [];
  const secretPattern = /(?:AKIA[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9_]{20,}|sk_(?:live|test)_[A-Za-z0-9]{16,}|-----BEGIN (?:RSA |EC )?PRIVATE KEY-----|(?:api[_-]?key|secret|token)\s*[:=]\s*["'][A-Za-z0-9_\-.]{20,}["'])/gi;
  for (const match of text.matchAll(secretPattern)) secretMatches.push(match[0].slice(0, 120));
  return { endpoints: [...endpoints], sourceMaps, secretMatches };
}

function addClientFindings(findings, text, pageUrl, contentType) {
  if (!text) return extractClientInventory("", pageUrl);
  const client = extractClientInventory(text, pageUrl);
  for (const endpoint of client.endpoints) {
    findings.push(finding(
      "client-api-endpoint",
      "info",
      "Client-side API endpoint was inventoried",
      endpoint,
      pageUrl,
      "Review the endpoint's authentication, authorization, rate limits, and data minimization separately.",
    ));
  }
  if (client.sourceMaps.length) {
    findings.push(finding(
      "public-source-map-reference",
      "low",
      "Client code references a source map",
      client.sourceMaps.slice(0, 3).join(" | "),
      pageUrl,
      "Publish source maps only when their exposure is intentional and ensure they contain no secrets or internal source that should remain private.",
    ));
  }
  if (client.secretMatches.length) {
    findings.push(finding(
      "potential-client-secret",
      "high",
      "Potential secret-like value is visible to clients",
      `${client.secretMatches.length} high-confidence secret-like pattern(s) observed in ${contentType || "client content"}.`,
      pageUrl,
      "Treat the value as exposed: revoke or rotate it, then move privileged operations behind a server-side authorization boundary.",
    ));
  }
  const sinkMatches = [...text.matchAll(/(?:\beval\s*\(|new\s+Function\s*\(|document\.write\s*\(|(?:innerHTML|outerHTML)\s*=|insertAdjacentHTML\s*\(|postMessage\s*\([^,]+,\s*["']\*["'])/gi)].map((match) => match[0]);
  if (sinkMatches.length) {
    findings.push(finding(
      "client-dangerous-sink",
      "low",
      "Client code contains a security-sensitive sink",
      `${sinkMatches.length} candidate sink(s): ${sinkMatches.slice(0, 4).join(", ")}.`,
      pageUrl,
      "Review data flow into the sink, prefer safe DOM APIs, and validate postMessage origins explicitly.",
    ));
  }
  if (/^application\/json\b/i.test(contentType || "")) {
    try {
      const value = JSON.parse(text);
      const sensitiveKeys = findSensitiveJsonKeys(value);
      if (sensitiveKeys.length) {
        findings.push(finding(
          "sensitive-data-in-json",
          "medium",
          "JSON response contains sensitive-looking fields",
          sensitiveKeys.slice(0, 8).join(", "),
          pageUrl,
          "Confirm the response is intentionally public and remove credentials, session material, and unnecessary personal data from client-visible JSON.",
        ));
      }
    } catch {
      // Non-JSON content-types occasionally contain invalid or partial JSON; inventory remains best-effort.
    }
  }
  return client;
}

function findSensitiveJsonKeys(value, path = "", result = []) {
  if (!value || typeof value !== "object" || result.length >= 20) return result;
  for (const [key, child] of Object.entries(value)) {
    const current = path ? `${path}.${key}` : key;
    if (/(?:password|passwd|secret|token|api[_-]?key|private[_-]?key|ssn|social[_-]?security)/i.test(key)) result.push(current);
    findSensitiveJsonKeys(child, current, result);
  }
  return result;
}

function addRedirectFindings(findings, html, pageUrl) {
  for (const link of extractLinks(html, pageUrl)) {
    const url = new URL(link);
    const redirectParameter = [...url.searchParams.keys()].find((key) => /^(?:next|url|redirect|return|continue|callback|destination)$/i.test(key));
    const value = redirectParameter ? url.searchParams.get(redirectParameter) : "";
    if (!value || !/^https?:\/\//i.test(value)) continue;
    findings.push(finding(
      "potential-open-redirect",
      "low",
      "Redirect-like parameter accepts an absolute URL",
      `${redirectParameter}=${value.slice(0, 180)}`,
      link.href,
      "Validate redirect destinations against an explicit allowlist and reject untrusted absolute URLs.",
    ));
  }
}

function uniqueFindings(findings) {
  const seen = new Set();
  return findings.filter((item) => {
    const key = `${item.id}|${item.location}|${item.evidence}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

async function checkWellKnownPaths(rootUrl, options, findings, controls = {}) {
  const paths = [
    "/robots.txt",
    "/sitemap.xml",
    "/.well-known/security.txt",
    "/.git/HEAD",
    "/.env",
    "/config.json",
    "/swagger.json",
    "/openapi.json",
    "/actuator/env",
  ];
  for (const path of paths) {
    const url = new URL(path, rootUrl);
    let result;
    try {
      result = await fetchBounded(url.href, options, { consumeRequest: controls.consumeRequest });
      controls.requestLog?.push(...result.requests);
      controls.progress?.("metadata-completed", { url: url.href, status: result.response.status });
    } catch (error) {
      if (error instanceof ScanBudgetError || error.name === "AbortError") throw error;
      continue;
    }
    if (result.response.status < 200 || result.response.status >= 300) continue;

    if (path === "/.git/HEAD" && /^\s*ref:\s+/i.test(result.body.text)) {
      findings.push(finding(
        "exposed-git-metadata",
        "high",
        "Git metadata is publicly readable",
        "The public .git/HEAD endpoint returned a Git reference.",
        url.href,
        "Remove repository metadata from the web root and rotate any credentials that may have been committed.",
      ));
    }
    if (path === "/robots.txt") {
      const sensitive = result.body.text.split(/\r?\n/).filter((line) => /^\s*disallow\s*:/i.test(line) && DANGEROUS_PATH_WORDS.test(line));
      if (sensitive.length) {
        findings.push(finding(
          "robots-discloses-sensitive-path",
          "info",
          "robots.txt names sensitive-looking paths",
          sensitive.slice(0, 5).join(" | "),
          url.href,
          "Treat robots.txt as public. Do not rely on it to protect administrative or private paths.",
        ));
      }
    }
    if (path === "/.well-known/security.txt") {
      findings.push(finding(
        "security-contact-published",
        "info",
        "Security contact is published",
        "A security.txt resource is available for responsible disclosure.",
        url.href,
        "Keep the contact and policy links current.",
      ));
      const lines = result.body.text.split(/\r?\n/).filter(Boolean);
      if (!lines.some((line) => /^contact\s*:/i.test(line))) {
        findings.push(finding(
          "security-contact-missing",
          "low",
          "security.txt has no Contact field",
          "The published security.txt document does not contain a Contact field.",
          url.href,
          "Add a monitored security contact address or URL so researchers can report issues responsibly.",
        ));
      }
      const expires = lines.find((line) => /^expires\s*:/i.test(line))?.split(":").slice(1).join(":").trim();
      if (!expires || Number.isNaN(Date.parse(expires))) {
        findings.push(finding(
          "security-contact-expiry-invalid",
          "low",
          "security.txt has no valid Expires field",
          "The security.txt document is missing a parseable Expires field.",
          url.href,
          "Publish a future RFC 9116 Expires timestamp and renew it before it lapses.",
        ));
      } else if (Date.parse(expires) < Date.now()) {
        findings.push(finding(
          "security-contact-expired",
          "low",
          "security.txt has expired",
          `The security.txt Expires value is in the past: ${expires}.`,
          url.href,
          "Renew the security.txt document with a future Expires timestamp.",
        ));
      }
    }
    if (path === "/.env" && result.body.text.trim()) {
      findings.push(finding(
        "exposed-environment-file",
        "high",
        "Environment file is publicly readable",
        "The /.env endpoint returned a non-empty response.",
        url.href,
        "Remove environment files from the web root, rotate any values they contained, and block the path at the server or CDN.",
      ));
    }
    if (["/config.json", "/swagger.json", "/openapi.json", "/actuator/env"].includes(path) && result.body.text.trim()) {
      findings.push(finding(
        "public-configuration-or-api-description",
        "medium",
        "Public configuration or API description is readable",
        `${path} returned a non-empty response and may disclose implementation or environment details.`,
        url.href,
        "Confirm the document is intentionally public, remove secrets and internal endpoints, and protect operational configuration.",
      ));
    }
  }
}

async function writeCheckpoint(path, state) {
  if (!path) return;
  const temporaryPath = `${path}.${process.pid}.tmp`;
  await writeFile(temporaryPath, `${JSON.stringify({ schemaVersion: 2, ...state }, null, 2)}\n`, "utf8");
  await rename(temporaryPath, path);
}

function isInScope(value, scope) {
  try {
    assertInScope(value, scope);
    return true;
  } catch {
    return false;
  }
}

function normalizeScanOptions(overrides, scope) {
  const options = { ...DEFAULTS, ...overrides, scope, authHeaders: normalizeAuthHeaders(overrides.authHeaders) };
  for (const [name, minimum] of [["maxPages", 1], ["maxResources", 1], ["maxRequests", 1], ["maxResponseBytes", 1], ["timeoutMs", 1], ["maxElapsedMs", 1], ["delayMs", 0], ["maxRedirects", 0]]) {
    if (!Number.isInteger(options[name]) || options[name] < minimum) throw new Error(`${name} must be an integer >= ${minimum}.`);
  }
  return options;
}

function normalizeAuthHeaderOrigins(value, rootOrigin) {
  const origins = value === undefined ? [rootOrigin] : value;
  if (!Array.isArray(origins) || origins.length === 0) throw new Error("authHeaderOrigins must be a non-empty array when provided.");
  return [...new Set(origins.map((origin) => {
    const url = new URL(origin);
    if (!/^https?:$/.test(url.protocol) || url.username || url.password || url.pathname !== "/" || url.search || url.hash) throw new Error(`Auth header origin must be a clean http(s) origin: ${origin}`);
    return url.origin;
  }))];
}

export async function scan(target, overrides = {}) {
  const root = normalizeTarget(target);
  const scope = normalizeScope(overrides.scope || { allowedOrigins: [root.origin] });
  assertInScope(root.href, scope);
  const options = normalizeScanOptions(overrides, scope);
  options.authHeaderOrigins = normalizeAuthHeaderOrigins(overrides.authHeaderOrigins, root.origin);
  const resume = overrides.resume;
  if (resume?.target && resume.target !== root.href) throw new Error("Checkpoint target does not match --target.");
  if (resume?.scope && JSON.stringify({ allowedOrigins: resume.scope.allowedOrigins, includePaths: resume.scope.includePaths || [], excludePaths: resume.scope.excludePaths || [] }) !== JSON.stringify({ allowedOrigins: scope.allowedOrigins, includePaths: scope.includePaths, excludePaths: scope.excludePaths })) throw new Error("Checkpoint scope does not match the supplied scope.");
  const startedAt = resume?.startedAt || new Date().toISOString();
  const findings = [...(resume?.findings || [])];
  const pages = [...(resume?.pages || [])];
  const resources = [...(resume?.resources || [])];
  const requestLog = [...(resume?.requestLog || [])];
  const inventoryPages = [...(resume?.inventoryPages || [])];
  const inventoryClientApiEndpoints = [...(resume?.inventoryClientApiEndpoints || [])];
  const inventorySourceMaps = [...(resume?.inventorySourceMaps || [])];
  const queued = new Map((resume?.queued || [{ url: root.href, kind: "page" }]).map((entry) => [entry.url || entry, typeof entry === "string" ? "page" : entry.kind || "page"]));
  const visited = new Set(resume?.visited || []);
  let firstResult;
  let rootAnalyzed = pages.length > 0 || resources.length > 0;
  let requestCount = resume?.requestCount || requestLog.length;
  let stopReason = resume?.stopReason || "";
  const scanClock = Date.now();
  const progress = (phase, extra = {}) => {
    try { options.onProgress?.({ phase, target: root.href, pagesScanned: pages.length, resourcesScanned: resources.length, requestsMade: requestCount, elapsedMs: Date.now() - scanClock, ...extra }); } catch { /* progress observers cannot affect scanning */ }
  };
  const consumeRequest = () => {
    if (requestCount >= options.maxRequests) return false;
    requestCount += 1;
    return true;
  };
  const canContinue = () => {
    if (options.signal?.aborted) throw options.signal.reason || new DOMException("The scan was canceled.", "AbortError");
    if (Date.now() - scanClock >= options.maxElapsedMs) {
      stopReason = "Maximum scan duration reached.";
      return false;
    }
    return true;
  };

  const enqueue = (url, kind) => {
    const href = new URL(url).href;
    if ([...new URL(href).searchParams.keys()].some((key) => SENSITIVE_QUERY_KEYS.test(key))) return;
    if (!isInScope(href, scope) || visited.has(href) || queued.has(href)) return;
    const queuedPages = [...queued.values()].filter((item) => item === "page").length;
    const queuedResources = [...queued.values()].filter((item) => item !== "page").length;
    if (kind === "page" && pages.length + queuedPages >= options.maxPages) return;
    if (kind !== "page" && resources.length + queuedResources >= options.maxResources) return;
    queued.set(href, kind);
  };

  progress("started");
  while (queued.size && pages.length < options.maxPages && !stopReason) {
    if (!canContinue()) break;
    const [nextUrl, kind] = queued.entries().next().value;
    queued.delete(nextUrl);
    if (visited.has(nextUrl)) continue;
    visited.add(nextUrl);

    let result;
    try {
      progress("request-started", { url: nextUrl, kind });
      result = await fetchBounded(nextUrl, options, { consumeRequest });
    } catch (error) {
      if (error instanceof ScanBudgetError) {
        stopReason = error.message;
        break;
      }
      if (error.name === "AbortError") throw error;
      requestLog.push({ url: nextUrl, status: null, elapsedMs: null, error: error.message });
      findings.push(finding(
        "request-failed",
        "info",
        "Request could not be completed",
        error.name === "AbortError" ? "The request timed out." : error.message,
        nextUrl,
        "Verify the target is available and repeat the scan with an appropriate timeout.",
      ));
      progress("request-failed", { url: nextUrl, error: error.message });
      continue;
    }

    if (!firstResult) firstResult = result;
    requestLog.push(...result.requests);
    progress("request-completed", { url: nextUrl, kind, status: result.response.status });
    const contentType = headerValue(result.response.headers, "content-type");
    const isHtml = kind === "page" && (/(?:text\/html|application\/xhtml\+xml)/i.test(contentType) || !contentType);
    const entry = {
      requestedUrl: redactUrl(nextUrl),
      finalUrl: redactUrl(result.finalUrl),
      status: result.response.status,
      contentType,
      bytesRead: new TextEncoder().encode(result.body.text).byteLength,
      truncated: result.body.truncated,
      kind,
    };
    if (isHtml) pages.push(entry); else resources.push(entry);

    if (!rootAnalyzed) {
      rootAnalyzed = true;
      addHeaderFindings(findings, result.response.headers, result.finalUrl);
      addCookieFindings(findings, result.response.headers, result.finalUrl);
      if (root.protocol === "http:") {
        if (new URL(result.finalUrl).protocol === "https:") {
          findings.push(finding("http-redirects-to-https", "info", "HTTP redirects to HTTPS", "The target redirected the initial HTTP request to HTTPS.", root.href, "Keep the redirect and consider HSTS after confirming all subdomains are HTTPS-ready."));
        } else {
          findings.push(finding("site-served-over-http", "high", "Site is served over HTTP", "The initial target and final response are not encrypted with HTTPS.", result.finalUrl, "Deploy HTTPS and redirect every HTTP request to the HTTPS origin."));
        }
      }
      if (new URL(result.finalUrl).protocol === "https:" && !headerValue(result.response.headers, "strict-transport-security")) {
        findings.push(finding("missing-hsts", "low", "Strict transport security is missing", "The HTTPS response does not include Strict-Transport-Security.", result.finalUrl, "After confirming all relevant subdomains support HTTPS, add a carefully staged HSTS policy."));
      }
    }

    if (isHtml) {
      addHtmlFindings(findings, result.body.text, result.finalUrl, root.origin);
      addRedirectFindings(findings, result.body.text, result.finalUrl);
      const pageInventory = extractPageInventory(result.body.text, redactUrl(result.finalUrl), root.origin);
      const client = addClientFindings(findings, result.body.text, result.finalUrl, contentType);
      pageInventory.clientApiEndpoints = client.endpoints;
      inventoryClientApiEndpoints.push(...client.endpoints);
      inventorySourceMaps.push(...client.sourceMaps);
      inventoryPages.push(pageInventory);
      if (!result.body.truncated) {
        for (const link of extractLinks(result.body.text, result.finalUrl)) {
          const resource = RESOURCE_EXTENSIONS.test(link.pathname + link.search);
          if (!resource && SKIPPED_EXTENSIONS.test(link.pathname + link.search)) continue;
          enqueue(link.href, resource ? "resource" : "page");
        }
        for (const tag of extractAttributeTags(result.body.text, "script")) {
          const source = attribute(tag, "src");
          if (!source) continue;
          try {
            const scriptUrl = new URL(source, result.finalUrl);
            if (isInScope(scriptUrl.href, scope)) enqueue(scriptUrl.href, "resource");
          } catch {
            // Ignore malformed script URLs.
          }
        }
      }
    } else if (/^(?:application\/javascript|text\/javascript|application\/json|text\/json)\b/i.test(contentType) || RESOURCE_EXTENSIONS.test(nextUrl)) {
      const client = addClientFindings(findings, result.body.text, result.finalUrl, contentType);
      inventoryClientApiEndpoints.push(...client.endpoints);
      inventorySourceMaps.push(...client.sourceMaps);
    }

      await writeCheckpoint(options.checkpointPath, {
      status: "in-progress",
      target: root.href,
      scope: { name: scope.name, allowedOrigins: scope.allowedOrigins, includePaths: scope.includePaths, excludePaths: scope.excludePaths },
      startedAt,
      queued: [...queued].map(([url, entryKind]) => ({ url, kind: entryKind })),
      visited: [...visited],
      pages,
      resources,
      requestLog,
      requestCount,
      stopReason,
      inventoryPages,
      inventoryClientApiEndpoints,
      inventorySourceMaps,
      findings,
    });
    if (queued.size && options.delayMs > 0) await new Promise((resolve) => setTimeout(resolve, options.delayMs));
  }

  if (!stopReason && canContinue()) {
    try {
      await checkWellKnownPaths(root, options, findings, { consumeRequest, requestLog, progress });
    } catch (error) {
      if (error instanceof ScanBudgetError) stopReason = error.message;
      else if (error.name === "AbortError") throw error;
    }
  }
  if (!stopReason && queued.size) stopReason = pages.length >= options.maxPages ? "Maximum page budget reached." : "Maximum resource budget reached.";
  let infrastructure = { metadata: null, findings: [], skipped: "Infrastructure checks disabled." };
  if (options.checkInfrastructure) infrastructure = await inspectInfrastructure(root.href, options);
  for (const item of infrastructure.findings || []) findings.push(finding(item.id, item.severity, item.title, item.evidence, item.location, item.remediation));
  const finalFindings = uniqueFindings(findings);
  const attackPaths = buildAttackPaths(finalFindings, options.attackPathRules || DEFAULT_ATTACK_PATH_RULES);
  const risk = calculateRisk(finalFindings, attackPaths);
  const counts = finalFindings.reduce((result, item) => {
    result[item.severity] = (result[item.severity] || 0) + 1;
    return result;
  }, {});
  const confidence = finalFindings.reduce((result, item) => {
    result[item.confidence || "unknown"] = (result[item.confidence || "unknown"] || 0) + 1;
    return result;
  }, {});

  const limits = { ...options };
  delete limits.scope;
  delete limits.authHeaders;
  delete limits.resume;
  delete limits.checkpointPath;
  delete limits.attackPathRules;
  delete limits.signal;
  delete limits.onProgress;
  const elapsedMs = Date.now() - scanClock;
  const report = {
    schemaVersion: 2,
    scanner: { name: "SentinelScan", version: "0.5.1", mode: "bounded-passive" },
    target: root.href,
    scope: { name: scope.name, allowedOrigins: scope.allowedOrigins, includePaths: scope.includePaths, excludePaths: scope.excludePaths },
    startedAt,
    finishedAt: new Date().toISOString(),
    limits,
    summary: { pagesScanned: pages.length, resourcesScanned: resources.length, requestsMade: requestCount, elapsedMs, termination: stopReason || "queue-exhausted", findings: finalFindings.length, bySeverity: counts, byConfidence: confidence, attackPaths: attackPaths.length, riskScore: risk.score, riskGrade: risk.grade },
    pages,
    resources,
    requests: requestLog,
    infrastructure,
    inventory: {
      pages: inventoryPages,
      totals: {
        links: inventoryPages.reduce((total, page) => total + page.links, 0),
        forms: inventoryPages.reduce((total, page) => total + page.forms, 0),
        passwordForms: inventoryPages.reduce((total, page) => total + page.passwordForms, 0),
        scripts: inventoryPages.reduce((total, page) => total + page.scripts, 0),
        externalScripts: inventoryPages.reduce((total, page) => total + page.externalScripts, 0),
        inlineScripts: inventoryPages.reduce((total, page) => total + (page.inlineScripts || 0), 0),
        jsonScripts: inventoryPages.reduce((total, page) => total + (page.jsonScripts || 0), 0),
        clientApiEndpoints: [...new Set(inventoryClientApiEndpoints)],
        sourceMaps: [...new Set(inventorySourceMaps)],
      },
    },
    findings: finalFindings,
    attackPaths,
    risk,
    notes: [
      "This report contains observations from safe GET requests only.",
      "A finding is a lead for review, not proof of exploitability.",
      "Repeated observations receive diminishing risk weight so crawl depth does not dominate prioritization.",
      `Execution budget: ${requestCount}/${options.maxRequests} requests, ${elapsedMs}ms/${options.maxElapsedMs}ms.`,
      stopReason ? `Scan stopped early: ${stopReason}` : "Scan completed its available queue.",
      firstResult?.finalUrl ? `Initial request resolved to ${redactUrl(firstResult.finalUrl)}.` : "The initial request did not complete.",
      infrastructure.skipped ? infrastructure.skipped : "Infrastructure metadata checks were enabled.",
    ],
  };
  await writeCheckpoint(options.checkpointPath, { status: "complete", target: root.href, scope: report.scope, startedAt, finishedAt: report.finishedAt, report });
  return report;
}

export { DEFAULTS };
