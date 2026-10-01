import { createHash } from "node:crypto";
import { assertInScope, assertOriginInScope, normalizeScope } from "./scope.mjs";
import { inspectInfrastructure } from "./infrastructure.mjs";
import { buildAttackPaths, calculateRisk, DEFAULT_ATTACK_PATH_RULES } from "./risk.mjs";
import { fetchWithNetworkPolicy } from "./network-policy.mjs";
import { DETECTOR_CATALOG, getDetector } from "./detector-registry.mjs";
import { actionableFindings, applyTriage, normalizeSuppressions, triageCounts } from "./triage.mjs";
import { fetchRendered } from "./browser-renderer.mjs";
import { addIntegrity, buildScanIdentity, verifyIntegrity } from "./provenance.mjs";
import { writePrivateFileAtomic } from "./private-file.mjs";

export const MAX_SCAN_LIMITS = Object.freeze({
  maxPages: 500,
  maxRedirects: 10,
  maxResponseBytes: 10_000_000,
  timeoutMs: 60_000,
  delayMs: 60_000,
  maxResources: 1_000,
  maxRequests: 5_000,
  maxElapsedMs: 900_000,
});

const DEFAULTS = Object.freeze({
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
  allowPrivateNetwork: false,
  rendered: false,
  confirmRendered: false,
});

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
const SENSITIVE_ASSIGNMENT = /\b(?:authorization|api[_-]?key|client[_-]?secret|password|passwd|secret|session|signature|sig|token|access[_-]?token|refresh[_-]?token)\b\s*[=:]\s*[^&\s,;]+/i;

function isLikelyResourceUrl(url) {
  return RESOURCE_EXTENSIONS.test(url.pathname + url.search) || /\/(?:api|graphql|swagger|openapi)(?:\/|$)/i.test(url.pathname);
}

export function normalizeTarget(value) {
  const url = new URL(value);
  if (!/^https?:$/.test(url.protocol)) {
    throw new Error("Target must use http:// or https://.");
  }
  if (url.username || url.password) {
    throw new Error("Targets containing embedded usernames or passwords are not accepted.");
  }
  if (containsSensitiveUrlData(url.href)) {
    throw new Error("Targets containing credential-shaped query parameters are not accepted; use authorized request headers instead.");
  }
  url.hash = "";
  return url;
}

export function redactUrl(value) {
  const url = new URL(value);
  url.username = "";
  url.password = "";
  url.hash = "";
  const parameters = [...url.searchParams.entries()];
  url.search = "";
  for (const [key, value] of parameters) {
    url.searchParams.append(key, SENSITIVE_QUERY_KEYS.test(key) ? "[REDACTED]" : redactNestedUrl(value));
  }
  return url.href;
}

function redactNestedUrl(value) {
  const text = String(value);
  const decoded = decodeRepeated(text);
  if (SENSITIVE_ASSIGNMENT.test(decoded) || (decoded !== text && /%[0-9a-f]{2}/i.test(decoded))) return "[REDACTED]";
  try {
    const nested = new URL(value);
    if (/^https?:$/.test(nested.protocol)) return redactUrl(nested.href);
  } catch {
    // The value is not a URL; the generic secret redaction below still applies.
  }
  return text.replace(/(\b(?:authorization|api[_-]?key|client[_-]?secret|password|passwd|secret|session|signature|sig|token|access[_-]?token|refresh[_-]?token)\b\s*[=:]\s*)([^&\s,;]+)/gi, "$1[REDACTED]");
}

function containsSensitiveUrlData(value, depth = 0) {
  if (depth > 3) return true;
  let url;
  try {
    url = new URL(value);
  } catch {
    return false;
  }
  if (url.username || url.password) return true;
  let fragment = decodeRepeated(url.hash.slice(1));
  if (/%[0-9a-f]{2}/i.test(fragment)) return true;
  if (SENSITIVE_ASSIGNMENT.test(fragment)) return true;
  for (const [key, child] of url.searchParams) {
    if (SENSITIVE_QUERY_KEYS.test(key)) return true;
    const decodedChild = decodeRepeated(child);
    if (/%[0-9a-f]{2}/i.test(decodedChild)) return true;
    if (SENSITIVE_ASSIGNMENT.test(decodedChild)) return true;
    const nested = /^\/\//.test(decodedChild) ? `https:${decodedChild}` : decodedChild;
    if (/^https?:\/\//i.test(nested) && containsSensitiveUrlData(nested, depth + 1)) return true;
  }
  return false;
}

function decodeRepeated(value) {
  let current = String(value ?? "");
  for (let attempt = 0; attempt < 32; attempt += 1) {
    try {
      const decoded = decodeURIComponent(current);
      if (decoded === current) break;
      current = decoded;
    } catch {
      break;
    }
  }
  return current;
}

export function redactText(value) {
  let text = String(value ?? "");
  text = text.replace(/\bhttps?:\/\/[^\s<>"']+/gi, (candidate) => {
    const suffix = candidate.match(/[),.;!?]+$/)?.[0] || "";
    const prefix = suffix ? candidate.slice(0, -suffix.length) : candidate;
    try { return `${redactUrl(prefix)}${suffix}`; } catch { return candidate; }
  });
  return redactNestedUrl(text);
}

function finding(id, severity, title, evidence, location, remediation) {
  const detector = getDetector(id);
  if (!detector) throw new Error(`Unknown detector ID: ${id}`);
  if (detector.severity !== severity) throw new Error(`Detector ${id} emitted severity ${severity}, expected ${detector.severity}.`);
  const safeLocation = redactUrl(location);
  const url = new URL(safeLocation);
  const fingerprintInput = `${id}|${url.origin}${url.pathname}`;
  const fingerprint = createHash("sha256").update(fingerprintInput).digest("hex").slice(0, 16);
  return { id, severity, title, evidence: redactText(evidence), location: safeLocation, remediation, fingerprint, category: detector.category, confidence: detector.confidence, confidenceScore: detector.confidenceScore, status: detector.status, observedAt: new Date().toISOString() };
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
  if (!response.body) return { text: "", truncated: false, bytesRead: 0 };

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
      if (signal?.aborted) throw abortError(signal);
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
  return { text: new TextDecoder().decode(bytes), truncated, bytesRead: bytes.byteLength };
}

function abortError(signal) {
  return signal?.reason || new DOMException("The scan was canceled.", "AbortError");
}

function sleep(ms, signal) {
  return new Promise((resolve, reject) => {
    if (signal?.aborted) return reject(abortError(signal));
    const onAbort = () => {
      clearTimeout(timer);
      reject(abortError(signal));
    };
    const timer = setTimeout(() => {
      signal?.removeEventListener("abort", onAbort);
      resolve();
    }, ms);
    signal?.addEventListener("abort", onAbort, { once: true });
  });
}

function assertBeforeDeadline(deadlineAt) {
  if (deadlineAt !== undefined && Date.now() >= deadlineAt) throw new ScanBudgetError("Maximum scan duration reached.");
}

/**
 * Enforces a minimum quiet gap between consecutive outbound requests.
 *
 * Every request the scanner makes (crawl pages, resources, each redirect hop,
 * and the fixed well-known path checks) goes through fetchBounded(), which calls
 * wait() before and done() after. The gap is measured from the end of one request
 * to the start of the next, and waiting is cancelable through the scan signal.
 */
function createPacer(delayMs, signal, deadlineAt) {
  let readyAt = 0;
  return {
    async wait() {
      assertBeforeDeadline(deadlineAt);
      if (!(delayMs > 0)) return;
      let remaining = readyAt - Date.now();
      while (remaining > 0) {
        const deadlineRemaining = deadlineAt === undefined ? remaining : deadlineAt - Date.now();
        if (deadlineRemaining <= 0) throw new ScanBudgetError("Maximum scan duration reached.");
        await sleep(Math.min(remaining, deadlineRemaining), signal);
        remaining = readyAt - Date.now();
      }
      assertBeforeDeadline(deadlineAt);
    },
    done() {
      readyAt = Date.now() + delayMs;
    },
  };
}

async function fetchBounded(startUrl, options, controls = {}) {
  if (options.rendered) return fetchRendered(startUrl, options, controls);
  let current = new URL(startUrl);
  const chain = [];
  const requests = [];

  for (let hop = 0; hop <= options.maxRedirects; hop += 1) {
    if (options.signal?.aborted) throw abortError(options.signal);
    await controls.pacer?.wait();
    assertInScope(current.href, options.scope);
    if (containsSensitiveUrlData(current.href)) throw new Error("Credential-shaped query parameter blocked; use authorized request headers instead.");
    assertBeforeDeadline(controls.deadlineAt);
    if (controls.consumeRequest && !controls.consumeRequest()) throw new ScanBudgetError("Maximum request budget reached.");
    const controller = new AbortController();
    const requestStarted = Date.now();
    const remaining = controls.deadlineAt === undefined ? options.timeoutMs : controls.deadlineAt - Date.now();
    if (remaining <= 0) throw new ScanBudgetError("Maximum scan duration reached.");
    const requestTimeoutMs = Math.min(options.timeoutMs, remaining);
    const timeoutReason = new DOMException(
      requestTimeoutMs < options.timeoutMs ? "The scan duration expired." : "The request timed out.",
      "AbortError",
    );
    const timeout = setTimeout(() => controller.abort(timeoutReason), Math.max(1, requestTimeoutMs));
    const abortParent = () => controller.abort(options.signal.reason);
    options.signal?.addEventListener("abort", abortParent, { once: true });
    let response;
    let recorded = false;
    try {
      response = await fetchWithNetworkPolicy(current, {
        method: "GET",
        signal: controller.signal,
        allowPrivateNetwork: options.allowPrivateNetwork,
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
        requests.push({ url: redactUrl(current.href), status, elapsedMs: Date.now() - requestStarted, redirectedTo: redactUrl(next.href) });
        recorded = true;
        assertInScope(next.href, options.scope);
        if (containsSensitiveUrlData(next.href)) throw new Error("Credential-shaped redirect query parameter blocked; use authorized request headers instead.");
        chain.push({ from: current.href, to: next.href, status });
        current = next;
        continue;
      }

      const body = await readBody(response, options.maxResponseBytes, controller.signal);
      requests.push({ url: redactUrl(current.href), status, elapsedMs: Date.now() - requestStarted, bytesRead: body.bytesRead });
      recorded = true;
      return {
        requestedUrl: startUrl,
        finalUrl: current.href,
        response,
        body,
        chain,
        requests,
      };
    } catch (error) {
      if (!recorded) requests.push({ url: redactUrl(current.href), status: response?.status ?? null, elapsedMs: Date.now() - requestStarted, error: redactText(error?.message || "Request failed."), ...(error?.code ? { code: error.code } : {}) });
      error.requestLog = requests;
      if (controls.deadlineAt !== undefined && Date.now() >= controls.deadlineAt && !options.signal?.aborted) {
        const budgetError = new ScanBudgetError("Maximum scan duration reached.");
        budgetError.requestLog = requests;
        throw budgetError;
      }
      throw error;
    } finally {
      clearTimeout(timeout);
      options.signal?.removeEventListener("abort", abortParent);
      controls.pacer?.done();
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
    const maxAgeMatch = hsts.match(/max-age\s*=\s*(\d+)/i);
    const maxAge = Number(maxAgeMatch?.[1] || 0);
    if (!maxAgeMatch || maxAge < 15_552_000) {
      findings.push(finding(
        "weak-hsts-duration",
        "low",
        "Strict transport security duration is short",
        maxAgeMatch ? `HSTS max-age is ${maxAge} seconds, below the six-month baseline.` : "HSTS does not contain a valid max-age directive.",
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

  const frameOptions = headerValue(headers, "x-frame-options");
  const hasFrameProtection = /^(?:deny|sameorigin)$/i.test(frameOptions) ||
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
      "info",
      "CORS credential flag is ignored with a wildcard origin",
      "Browsers reject credentialed CORS responses when Access-Control-Allow-Origin is *, so this combination does not grant credentialed cross-origin access.",
      url,
      "If credentialed cross-origin access is required, return an explicit trusted origin; otherwise confirm the endpoint is intentionally public.",
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
  const match = tag.match(new RegExp(`\\b${name}\\s*=\\s*(?:"([^"]*)"|'([^']*)'|([^\\s"'=<>\`]+))`, "i"));
  return (match?.[1] ?? match?.[2] ?? match?.[3] ?? "").trim();
}

function hasAttribute(tag, name) {
  return new RegExp(`\\s${name}(?=\\s|=|/?>)`, "i").test(tag);
}

function extractFormBlocks(html) {
  return [...html.matchAll(/<form\b[^>]*>[\s\S]*?(?:<\/form>|$)/gi)].map((match) => match[0]);
}

function hasPasswordInput(formHtml) {
  return extractAttributeTags(formHtml, "input").some((tag) => attribute(tag, "type").toLowerCase() === "password");
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

  for (const formHtml of extractFormBlocks(html)) {
    const form = extractAttributeTags(formHtml, "form")[0] || formHtml;
    const formAction = attribute(form, "action");
    let formUrl;
    try {
      formUrl = formAction ? new URL(formAction, pageUrl) : new URL(pageUrl);
    } catch {
      continue;
    }
    const hasPassword = hasPasswordInput(formHtml);
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
    if (hasPassword && (attribute(form, "method") || "get").toLowerCase() === "get") {
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
      if (frameUrl.origin !== new URL(pageUrl).origin && !hasAttribute(iframe, "sandbox")) {
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
  const formBlocks = extractFormBlocks(html);
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
    passwordForms: formBlocks.filter(hasPasswordInput).length,
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
  const sourceMaps = [...text.matchAll(/sourceMappingURL\s*=\s*([^\s*]+)/gi)]
    .map((match) => normalizeClientEndpoint(match[1].trim(), pageUrl))
    .filter(Boolean);
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
  if (/^(?:application\/json|text\/json)\b/i.test(contentType || "")) {
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

function isHtmlFallback(text, contentType) {
  return /html/i.test(contentType || "") || /^\s*(?:<!doctype\s+html|<html\b)/i.test(text);
}

function looksLikeHtmlDocument(text, contentType) {
  if (/html/i.test(contentType || "")) return true;
  if (contentType) return false;
  return /^\s*(?:<!doctype\s+html|<(?:html|head|body|title|meta|link|script|style|a|form|input|button|img|iframe|div|main|section|article|p|ul|ol|table)\b)/i.test(text);
}

function parseJsonDocument(text, contentType) {
  if (!/^(?:application\/json|text\/json)\b/i.test(contentType || "") && isHtmlFallback(text, contentType)) return null;
  try {
    const value = JSON.parse(text);
    return value && typeof value === "object" ? value : null;
  } catch {
    return null;
  }
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
  const startIndex = Number.isInteger(controls.startIndex) ? Math.max(0, Math.min(paths.length, controls.startIndex)) : 0;
  for (let index = startIndex; index < paths.length; index += 1) {
    const path = paths[index];
    const advance = () => controls.onIndex?.(index + 1);
    // Pacing can make this loop slow, so the wall-clock budget is re-checked per path.
    if (controls.canContinue && !controls.canContinue()) throw new ScanBudgetError("Maximum scan duration reached.");
    const url = new URL(path, rootUrl);
    let result;
    try {
      result = await fetchBounded(url.href, options, { consumeRequest: controls.consumeRequest, pacer: controls.pacer, deadlineAt: controls.deadlineAt });
      controls.requestLog?.push(...result.requests);
      controls.progress?.("metadata-completed", { url: url.href, status: result.response.status });
    } catch (error) {
      if (error.requestLog?.length) controls.requestLog?.push(...error.requestLog);
      // A cancellation by the operator must stop the scan; a slow or failing
      // well-known path must not.
      if (error instanceof ScanBudgetError || options.signal?.aborted) throw error;
      advance();
      continue;
    }
    if (result.response.status < 200 || result.response.status >= 300) {
      advance();
      continue;
    }

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
    const contentType = headerValue(result.response.headers, "content-type");
    if (path === "/.well-known/security.txt" && !isHtmlFallback(result.body.text, contentType)) {
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
    if (path === "/.env" && /^[A-Za-z_][A-Za-z0-9_]*\s*=/m.test(result.body.text) && !isHtmlFallback(result.body.text, contentType)) {
      findings.push(finding(
        "exposed-environment-file",
        "high",
        "Environment file is publicly readable",
        "The /.env endpoint returned a non-empty response.",
        url.href,
        "Remove environment files from the web root, rotate any values they contained, and block the path at the server or CDN.",
      ));
    }
    const jsonDocument = ["/config.json", "/swagger.json", "/openapi.json", "/actuator/env"].includes(path)
      ? parseJsonDocument(result.body.text, contentType)
      : null;
    const isApiDescription = ["/swagger.json", "/openapi.json"].includes(path) && jsonDocument && (jsonDocument.openapi || jsonDocument.swagger || jsonDocument.paths);
    if ((path === "/config.json" || path === "/actuator/env" ? jsonDocument : isApiDescription)) {
      findings.push(finding(
        "public-configuration-or-api-description",
        "medium",
        "Public configuration or API description is readable",
        `${path} returned a non-empty response and may disclose implementation or environment details.`,
        url.href,
        "Confirm the document is intentionally public, remove secrets and internal endpoints, and protect operational configuration.",
      ));
    }
    advance();
  }
}

async function writeCheckpoint(path, state) {
  if (!path) return;
  const checkpoint = addIntegrity({ schemaVersion: 2, ...state });
  await writePrivateFileAtomic(path, `${JSON.stringify(checkpoint, null, 2)}\n`);
}

function isInScope(value, scope) {
  try {
    assertInScope(value, scope);
    return true;
  } catch {
    return false;
  }
}

function normalizeCandidateUrl(value) {
  const url = new URL(value);
  if (!/^https?:$/.test(url.protocol) || url.username || url.password) throw new Error("Only clean http(s) URLs without embedded credentials may be scanned.");
  if (containsSensitiveUrlData(url.href)) throw new Error("Credential-shaped query parameter blocked; use authorized request headers instead.");
  url.hash = "";
  return url;
}

export function normalizeEmailDomain(value) {
  if (value === undefined || value === "") return undefined;
  if (typeof value !== "string" || !value.trim()) throw new Error("emailDomain must be a non-empty hostname.");
  const domain = value.trim().toLowerCase();
  const parsed = new URL(`https://${domain}`);
  if (parsed.username || parsed.password || parsed.port || parsed.pathname !== "/" || parsed.search || parsed.hash || parsed.hostname !== domain) {
    throw new Error("emailDomain must be a plain hostname without a scheme, port, path, or credentials.");
  }
  return parsed.hostname;
}

function normalizeScanOptions(overrides, scope, root) {
  const options = { ...DEFAULTS, scope, authHeaders: normalizeAuthHeaders(overrides.authHeaders) };
  for (const name of [
    "maxPages", "maxRedirects", "maxResponseBytes", "timeoutMs", "delayMs", "maxResources", "maxRequests", "maxElapsedMs",
    "checkInfrastructure", "certificateTransparency", "allowPrivateNetwork", "emailDomain", "dkimSelectors", "authHeaderOrigins", "checkpointPath",
    "resume", "attackPathRules", "signal", "onProgress", "suppressions", "rendered", "confirmRendered",
  ]) {
    if (overrides[name] !== undefined) options[name] = overrides[name];
  }
  for (const [name, minimum] of [["maxPages", 1], ["maxResources", 1], ["maxRequests", 1], ["maxResponseBytes", 1], ["timeoutMs", 1], ["maxElapsedMs", 1], ["delayMs", 0], ["maxRedirects", 0]]) {
    if (!Number.isInteger(options[name]) || options[name] < minimum || options[name] > MAX_SCAN_LIMITS[name]) {
      throw new Error(`${name} must be an integer from ${minimum} to ${MAX_SCAN_LIMITS[name]}.`);
    }
  }
  for (const name of ["checkInfrastructure", "certificateTransparency"]) {
    if (typeof options[name] !== "boolean") throw new Error(`${name} must be a boolean.`);
  }
  if (typeof options.allowPrivateNetwork !== "boolean") throw new Error("allowPrivateNetwork must be a boolean.");
  if (typeof options.rendered !== "boolean" || typeof options.confirmRendered !== "boolean") throw new Error("rendered and confirmRendered must be booleans.");
  if (options.rendered && !options.confirmRendered) throw new Error("Rendered mode requires confirmRendered: true because target JavaScript will execute.");
  options.suppressions = normalizeSuppressions(options.suppressions);
  if (options.certificateTransparency) options.checkInfrastructure = true;
  options.emailDomain = normalizeEmailDomain(options.emailDomain);
  if (options.checkInfrastructure && options.emailDomain && options.emailDomain !== root.hostname) {
    const inScope = ["https:", "http:"].some((protocol) => {
      try {
        assertOriginInScope(`${protocol}//${options.emailDomain}/`, scope);
        return true;
      } catch {
        return false;
      }
    });
    if (!inScope) throw new Error("emailDomain must be included in the explicit scan scope before infrastructure DNS checks are enabled.");
  }
  if (options.dkimSelectors !== undefined) {
    if (!Array.isArray(options.dkimSelectors) || options.dkimSelectors.length > 20 || options.dkimSelectors.some((selector) => typeof selector !== "string" || !/^[A-Za-z0-9_-]{1,63}$/.test(selector))) {
      throw new Error("dkimSelectors must contain at most 20 simple selector names.");
    }
    options.dkimSelectors = [...new Set(options.dkimSelectors)];
  }
  return options;
}

export function normalizeAuthHeaderOrigins(value, rootOrigin) {
  const origins = value === undefined ? [rootOrigin] : value;
  if (!Array.isArray(origins) || origins.length === 0) throw new Error("authHeaderOrigins must be a non-empty array when provided.");
  return [...new Set(origins.map((origin) => {
    const url = new URL(origin);
    if (!/^https?:$/.test(url.protocol) || url.username || url.password || url.pathname !== "/" || url.search || url.hash) throw new Error("Auth header origins must be clean http(s) origins.");
    return url.origin;
  }))];
}

function scopeIdentity(scope) {
  return JSON.stringify({
    allowedOrigins: [...(scope.allowedOrigins || [])].sort(),
    includePaths: [...(scope.includePaths || [])].sort(),
    excludePaths: [...(scope.excludePaths || [])].sort(),
  });
}

function validateResume(resume, root, scope, options) {
  if (resume === undefined) return;
  if (!resume || typeof resume !== "object" || resume.schemaVersion !== 2 || !resume.status) throw new Error("Checkpoint must be a schemaVersion 2 object with a status.");
  if (resume.integrity !== undefined && !verifyIntegrity(resume)) throw new Error("Checkpoint integrity hash does not match the supplied file.");
  if (resume.report?.integrity !== undefined && !verifyIntegrity(resume.report)) throw new Error("Completed checkpoint report integrity hash does not match the supplied file.");
  if (resume.target !== root.href) throw new Error("Checkpoint target does not match --target.");
  if (!resume.scope || scopeIdentity(resume.scope) !== scopeIdentity(scope)) throw new Error("Checkpoint scope does not match the supplied scope.");
  for (const field of ["queued", "deferred", "visited", "findings", "pages", "resources", "requestLog", "inventoryPages", "inventoryClientApiEndpoints", "inventorySourceMaps"]) {
    if (resume[field] !== undefined && !Array.isArray(resume[field])) throw new Error(`Checkpoint ${field} must be an array.`);
  }
  if (resume.requestCount !== undefined && (!Number.isInteger(resume.requestCount) || resume.requestCount < 0)) {
    throw new Error("Checkpoint requestCount must be a non-negative integer.");
  }
  if (resume.status === "in-progress") {
    const requestCount = resume.requestCount ?? resume.requestLog?.length ?? 0;
    if (requestCount > options.maxRequests || requestCount > MAX_SCAN_LIMITS.maxRequests) {
      throw new Error("Checkpoint requestCount exceeds the configured scan request budget.");
    }
    if ((resume.elapsedMs ?? 0) > options.maxElapsedMs) throw new Error("Checkpoint elapsedMs exceeds the configured scan duration budget.");
    if ((resume.pages?.length || 0) > options.maxPages) throw new Error("Checkpoint pages exceed the configured page budget.");
    if ((resume.resources?.length || 0) > options.maxResources) throw new Error("Checkpoint resources exceed the configured resource budget.");
  }
  if (resume.wellKnownIndex !== undefined && (!Number.isInteger(resume.wellKnownIndex) || resume.wellKnownIndex < 0 || resume.wellKnownIndex > 9)) {
    throw new Error("Checkpoint wellKnownIndex must be an integer from 0 to 9.");
  }
  if ([...(resume.queued || []), ...(resume.deferred || [])].some((entry) => typeof entry === "object" && entry?.kind !== undefined && !["page", "resource", "unknown"].includes(entry.kind))) {
    throw new Error("Checkpoint queue contains an unsupported entry kind.");
  }
  if (resume.status === "complete") {
    if (!resume.report || resume.report.target !== root.href || scopeIdentity(resume.report.scope) !== scopeIdentity(scope)) throw new Error("Completed checkpoint report does not match the supplied target and scope.");
  } else if (resume.status !== "in-progress") {
    throw new Error(`Unsupported checkpoint status: ${resume.status}`);
  }
}

export async function scan(target, overrides = {}) {
  if (!overrides || typeof overrides !== "object" || Array.isArray(overrides)) throw new Error("Scan options must be an object.");
  if (overrides.confirmAuthorized !== true) throw new Error("Refusing to scan without explicit authorization confirmation.");
  const root = normalizeTarget(target);
  const scope = normalizeScope(overrides.scope || { allowedOrigins: [root.origin] });
  assertInScope(root.href, scope);
  const options = normalizeScanOptions(overrides, scope, root);
  options.authHeaderOrigins = normalizeAuthHeaderOrigins(overrides.authHeaderOrigins, root.origin);
  const resume = overrides.resume;
  validateResume(resume, root, scope, options);
  if (resume?.status === "complete") return resume.report;
  const startedAt = resume?.startedAt || new Date().toISOString();
  const findings = [...(resume?.findings || [])];
  const pages = [...(resume?.pages || [])];
  const resources = [...(resume?.resources || [])];
  const requestLog = [...(resume?.requestLog || [])];
  const inventoryPages = [...(resume?.inventoryPages || [])];
  const inventoryClientApiEndpoints = [...(resume?.inventoryClientApiEndpoints || [])];
  const inventorySourceMaps = [...(resume?.inventorySourceMaps || [])];
  const queued = new Map();
  const deferred = [];
  const deferredUrls = new Set();
  const visited = new Set((resume?.visited || []).map((value) => normalizeCandidateUrl(value).href));
  let firstResult;
  let requestCount = resume?.requestCount ?? requestLog.length;
  let stopReason = "";
  let wellKnownIndex = resume?.wellKnownIndex ?? 0;
  const resumedElapsedMs = resume?.elapsedMs || 0;
  if (!Number.isInteger(resumedElapsedMs) || resumedElapsedMs < 0) throw new Error("Checkpoint elapsedMs must be a non-negative integer.");
  const scanClock = Date.now();
  const deadlineAt = scanClock + Math.max(0, options.maxElapsedMs - resumedElapsedMs);
  let pageBudgetReached = false;
  let resourceBudgetReached = false;
  let deferredOverflow = false;
  const maxDeferred = Math.max(1_000, Math.min(10_000, options.maxPages + options.maxResources));
  const addDeferred = (href, kind) => {
    if (deferredUrls.has(href) || queued.has(href) || visited.has(href)) return;
    if (deferred.length >= maxDeferred) {
      deferredOverflow = true;
      return;
    }
    deferred.push({ url: href, kind });
    deferredUrls.add(href);
  };
  const addQueued = (href, kind) => {
    if (visited.has(href) || queued.has(href) || deferredUrls.has(href)) return;
    const queuedPages = [...queued.values()].filter((item) => item !== "resource").length;
    const queuedResources = [...queued.values()].filter((item) => item === "resource").length;
    if (kind !== "resource" && pages.length + queuedPages >= options.maxPages) {
      pageBudgetReached = true;
      addDeferred(href, kind);
      return;
    }
    if (kind === "resource" && resources.length + queuedResources >= options.maxResources) {
      resourceBudgetReached = true;
      addDeferred(href, kind);
      return;
    }
    if (kind === "unknown" && resources.length >= options.maxResources) {
      resourceBudgetReached = true;
      addDeferred(href, kind);
      return;
    }
    queued.set(href, kind);
  };
  const resumeEntries = resume ? [...(resume.queued || []), ...(resume.deferred || [])] : [{ url: root.href, kind: "page" }];
  for (const entry of resumeEntries) {
    const rawUrl = typeof entry === "string" ? entry : entry?.url;
    if (!rawUrl) throw new Error("Checkpoint queue contains an invalid URL entry.");
    const candidate = normalizeCandidateUrl(rawUrl);
    assertInScope(candidate.href, scope);
    const entryKind = typeof entry === "string" ? "page" : entry.kind || "page";
    addQueued(candidate.href, entryKind === "page" && candidate.href !== root.href ? "unknown" : entryKind);
  }
  const progress = (phase, extra = {}) => {
    try { options.onProgress?.({ phase, target: root.href, pagesScanned: pages.length, resourcesScanned: resources.length, requestsMade: requestCount, elapsedMs: resumedElapsedMs + Date.now() - scanClock, ...extra }); } catch { /* progress observers cannot affect scanning */ }
  };
  const consumeRequest = () => {
    if (requestCount >= options.maxRequests) return false;
    requestCount += 1;
    return true;
  };
  const canContinue = () => {
    if (options.signal?.aborted) throw abortError(options.signal);
    if (Date.now() >= deadlineAt) {
      stopReason = "Maximum scan duration reached.";
      return false;
    }
    return true;
  };
  const remainingMs = () => Math.max(0, deadlineAt - Date.now());
  const pacer = createPacer(options.delayMs, options.signal, deadlineAt);

  const enqueue = (url, kind) => {
    let href;
    try {
      href = normalizeCandidateUrl(url).href;
    } catch {
      return;
    }
    if (!isInScope(href, scope) || visited.has(href) || queued.has(href) || deferredUrls.has(href)) return;
    const queuedPages = [...queued.values()].filter((item) => item !== "resource").length;
    const queuedResources = [...queued.values()].filter((item) => item === "resource").length;
    if (kind !== "resource" && pages.length + queuedPages >= options.maxPages) {
      pageBudgetReached = true;
      addDeferred(href, kind);
      return;
    }
    if (kind === "resource" && resources.length + queuedResources >= options.maxResources) {
      resourceBudgetReached = true;
      addDeferred(href, kind);
      return;
    }
    if (kind === "unknown" && resources.length >= options.maxResources) {
      resourceBudgetReached = true;
      addDeferred(href, kind);
      return;
    }
    queued.set(href, kind);
  };

  progress("started");
  while (queued.size && !stopReason) {
    if (!canContinue()) break;
    const [nextUrl, kind] = queued.entries().next().value;
    queued.delete(nextUrl);
    if (visited.has(nextUrl)) continue;
    if (kind === "unknown" && resources.length >= options.maxResources) {
      resourceBudgetReached = true;
      addDeferred(nextUrl, kind);
      stopReason = "Maximum resource budget reached.";
      break;
    }
    visited.add(nextUrl);

    let result;
    try {
      progress("request-started", { url: redactUrl(nextUrl), kind });
      result = await fetchBounded(nextUrl, options, { consumeRequest, pacer, deadlineAt });
    } catch (error) {
      if (error.requestLog?.length) requestLog.push(...error.requestLog);
      if (error instanceof ScanBudgetError) {
        visited.delete(nextUrl);
        queued.set(nextUrl, kind);
        stopReason = error.message;
        break;
      }
      if (error.code === "BROWSER_MODE_UNAVAILABLE") throw error;
      // Only an operator cancellation ends the scan. A request that merely timed
      // out is recorded as a finding and the scan carries on.
      if (options.signal?.aborted) throw error;
      const timedOut = error.name === "AbortError";
      const failure = timedOut ? `The request timed out after ${Math.min(options.timeoutMs, Math.max(1, options.maxElapsedMs - (resumedElapsedMs + Date.now() - scanClock)))} ms.` : error.message;
      if (!error.requestLog?.length) requestLog.push({ url: redactUrl(nextUrl), status: null, elapsedMs: null, error: redactText(failure), ...(error.code ? { code: error.code } : {}) });
      findings.push(finding(
        "request-failed",
        "info",
        "Request could not be completed",
        failure,
        redactUrl(nextUrl),
        "Verify the target is available and repeat the scan with an appropriate timeout.",
      ));
      progress("request-failed", { url: redactUrl(nextUrl), error: redactText(failure) });
      continue;
    }

    const isFirstResponse = !firstResult;
    if (isFirstResponse) firstResult = result;
    requestLog.push(...result.requests);
    progress("request-completed", { url: redactUrl(nextUrl), kind, status: result.response.status });
    const contentType = headerValue(result.response.headers, "content-type");
    const isHtml = kind !== "resource" && looksLikeHtmlDocument(result.body.text, contentType);
    const entry = {
      requestedUrl: redactUrl(nextUrl),
      finalUrl: redactUrl(result.finalUrl),
      status: result.response.status,
      contentType,
      bytesRead: result.body.bytesRead,
      truncated: result.body.truncated,
      kind: isHtml ? "page" : "resource",
    };
    const resourceLimitReached = !isHtml && resources.length >= options.maxResources;
    if (resourceLimitReached) resourceBudgetReached = true;
    if (isHtml) pages.push(entry); else if (!resourceLimitReached) resources.push(entry);

    if (isHtml) {
      addHeaderFindings(findings, result.response.headers, result.finalUrl);
      addCookieFindings(findings, result.response.headers, result.finalUrl);
      const finalProtocol = new URL(result.finalUrl).protocol;
      if (isFirstResponse) {
        if (root.protocol === "http:" && finalProtocol === "https:") {
          findings.push(finding("http-redirects-to-https", "info", "HTTP redirects to HTTPS", "The target redirected the initial HTTP request to HTTPS.", root.href, "Keep the redirect and consider HSTS after confirming all subdomains are HTTPS-ready."));
        } else if (root.protocol === "http:" && finalProtocol === "http:") {
          findings.push(finding("site-served-over-http", "high", "Site is served over HTTP", "The initial target and final response are not encrypted with HTTPS.", result.finalUrl, "Deploy HTTPS and redirect every HTTP request to the HTTPS origin."));
        }
      }
      if (root.protocol === "https:" && (result.chain || []).some((hop) => new URL(hop.from).protocol === "https:" && new URL(hop.to).protocol === "http:")) {
        findings.push(finding("https-redirects-to-http", "high", "HTTPS redirects to HTTP", "The navigation chain downgraded from HTTPS to an unencrypted HTTP URL.", result.finalUrl, "Reject HTTPS-to-HTTP redirects and keep the complete navigation path encrypted."));
      }
      if (finalProtocol === "https:" && !headerValue(result.response.headers, "strict-transport-security")) {
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
        for (const sourceMap of client.sourceMaps) enqueue(sourceMap, "resource");
        for (const link of extractLinks(result.body.text, result.finalUrl)) {
          const resource = isLikelyResourceUrl(link);
          if (!resource && SKIPPED_EXTENSIONS.test(link.pathname + link.search)) continue;
          enqueue(link.href, resource ? "resource" : "unknown");
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
    } else if (!resourceLimitReached && (/^(?:application\/javascript|text\/javascript|application\/json|text\/json)\b/i.test(contentType) || RESOURCE_EXTENSIONS.test(nextUrl))) {
      const client = addClientFindings(findings, result.body.text, result.finalUrl, contentType);
      inventoryClientApiEndpoints.push(...client.endpoints);
      inventorySourceMaps.push(...client.sourceMaps);
      if (!result.body.truncated) for (const sourceMap of client.sourceMaps) enqueue(sourceMap, "resource");
    }
    if (!isHtml && kind !== "resource" && resources.length >= options.maxResources) {
      resourceBudgetReached = true;
      stopReason = "Maximum resource budget reached.";
    }

    await writeCheckpoint(options.checkpointPath, {
      status: "in-progress",
      target: root.href,
      scope: { name: scope.name, allowedOrigins: scope.allowedOrigins, includePaths: scope.includePaths, excludePaths: scope.excludePaths },
      startedAt,
      elapsedMs: resumedElapsedMs + Date.now() - scanClock,
      queued: [...queued].map(([url, entryKind]) => ({ url, kind: entryKind })),
      deferred,
      wellKnownIndex,
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
  }

  if (!stopReason && canContinue()) {
    try {
      await checkWellKnownPaths(root, options, findings, { consumeRequest, requestLog, progress, pacer, canContinue, deadlineAt, startIndex: wellKnownIndex, onIndex: (index) => { wellKnownIndex = index; } });
    } catch (error) {
      if (error instanceof ScanBudgetError) stopReason = error.message;
      else if (options.signal?.aborted) throw error;
    }
  }
  if (!stopReason && queued.size) stopReason = pages.length >= options.maxPages ? "Maximum page budget reached." : "Maximum resource budget reached.";
  if (!stopReason && pageBudgetReached) stopReason = "Maximum page budget reached.";
  if (!stopReason && resourceBudgetReached) stopReason = "Maximum resource budget reached.";
  if (!stopReason && deferred.length) stopReason = pageBudgetReached ? "Maximum page budget reached." : "Maximum resource budget reached.";
  let infrastructure = { metadata: null, findings: [], skipped: "Infrastructure checks disabled." };
  if (options.checkInfrastructure && !stopReason) {
    try {
      infrastructure = await inspectInfrastructure(root.href, {
        ...options,
        remainingMs,
        beforeRequest: async () => {
          await pacer.wait();
          if (!canContinue()) throw new ScanBudgetError("Maximum scan duration reached.");
          if (!consumeRequest()) throw new ScanBudgetError("Maximum request budget reached.");
        },
        afterRequest: () => pacer.done(),
      });
    } catch (error) {
      if (error instanceof ScanBudgetError || error.code === "SCAN_BUDGET_EXHAUSTED") {
        stopReason = error.message;
        infrastructure = { metadata: null, findings: [], skipped: `Infrastructure checks stopped early: ${error.message}` };
      } else if (options.signal?.aborted) {
        throw error;
      } else {
        throw error;
      }
    }
  }
  for (const item of infrastructure.findings || []) findings.push(finding(item.id, item.severity, item.title, item.evidence, item.location, item.remediation));
  const finalFindings = applyTriage(uniqueFindings(findings), options.suppressions);
  const activeFindings = actionableFindings(finalFindings);
  const triage = triageCounts(finalFindings);
  const attackPaths = buildAttackPaths(activeFindings, options.attackPathRules || DEFAULT_ATTACK_PATH_RULES);
  const risk = calculateRisk(activeFindings, attackPaths);
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
  delete limits.confirmAuthorized;
  delete limits.suppressions;
  delete limits.confirmRendered;
  const elapsedMs = resumedElapsedMs + Date.now() - scanClock;
  const scanner = { name: "SentinelScan", version: "0.5.0", mode: options.rendered ? "bounded-rendered" : "bounded-passive" };
  const coverage = {
    complete: !stopReason,
    termination: stopReason || "queue-exhausted",
    pages: pages.length,
    resources: resources.length,
    requests: requestCount,
    deferred: deferred.length,
  };
  const scanIdentity = buildScanIdentity({
    scanner,
    scope: { name: scope.name, allowedOrigins: scope.allowedOrigins, includePaths: scope.includePaths, excludePaths: scope.excludePaths },
    limits,
    detectorCatalog: DETECTOR_CATALOG,
    attackPathRules: options.attackPathRules || DEFAULT_ATTACK_PATH_RULES,
  });
  const report = {
    schemaVersion: 2,
    scanner,
    target: root.href,
    scope: { name: scope.name, allowedOrigins: scope.allowedOrigins, includePaths: scope.includePaths, excludePaths: scope.excludePaths },
    startedAt,
    finishedAt: new Date().toISOString(),
    limits,
    scanIdentity,
    coverage,
     summary: { pagesScanned: pages.length, resourcesScanned: resources.length, requestsMade: requestCount, elapsedMs, termination: stopReason || "queue-exhausted", findings: finalFindings.length, ...triage, bySeverity: counts, byConfidence: confidence, attackPaths: attackPaths.length, riskScore: risk.score, riskGrade: risk.grade },
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
    suppressions: options.suppressions,
    attackPaths,
    risk,
    notes: [
      "This report contains observations from safe GET and HEAD requests only.",
      "A finding is a lead for review, not proof of exploitability.",
      "Repeated observations receive diminishing risk weight so crawl depth does not dominate prioritization.",
      `Execution budget: ${requestCount}/${options.maxRequests} requests, ${elapsedMs}ms/${options.maxElapsedMs}ms.`,
      stopReason ? `Scan stopped early: ${stopReason}` : "Scan completed its available queue.",
      ...(deferredOverflow ? ["The deferred queue reached its safety cap; rerun with a narrower scope or smaller pages before resuming."] : []),
      ...(requestLog.some((request) => request.code === "NETWORK_POLICY_BLOCKED") ? ["One or more requests were blocked by the private-network and URL network policy."] : []),
      firstResult?.finalUrl ? `Initial request resolved to ${redactUrl(firstResult.finalUrl)}.` : "The initial request did not complete.",
      infrastructure.skipped ? infrastructure.skipped : "Infrastructure metadata checks were enabled.",
    ],
  };
  const finalizedReport = addIntegrity(report);
  const resumable = Boolean(stopReason && /Maximum (?:scan duration reached|request budget reached|page budget reached|resource budget reached)\./.test(stopReason));
  await writeCheckpoint(options.checkpointPath, {
    status: resumable ? "in-progress" : "complete",
    target: root.href,
    scope: report.scope,
    startedAt,
    finishedAt: report.finishedAt,
    elapsedMs,
    queued: [...queued].map(([url, entryKind]) => ({ url, kind: entryKind })),
    deferred,
    wellKnownIndex,
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
    ...(resumable ? {} : { report: finalizedReport }),
  });
  return finalizedReport;
}

export { DEFAULTS };
