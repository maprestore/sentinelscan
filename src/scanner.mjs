import { createHash } from "node:crypto";
import { assertInScope, normalizeScope } from "./scope.mjs";
import { buildAttackPaths, calculateRisk } from "./risk.mjs";

const DEFAULTS = {
  maxPages: 20,
  maxRedirects: 5,
  maxResponseBytes: 1_000_000,
  timeoutMs: 8_000,
  delayMs: 250,
};

const SECURITY_HEADERS = [
  ["content-security-policy", "Content-Security-Policy", "low"],
  ["referrer-policy", "Referrer-Policy", "low"],
  ["permissions-policy", "Permissions-Policy", "low"],
];

const DANGEROUS_PATH_WORDS = /(?:admin|private|backup|staging|internal|config|secret|\.env)/i;
const SKIPPED_EXTENSIONS = /\.(?:7z|avi|bin|bmp|css|csv|docx?|gif|gz|ico|jpe?g|js|m4a|mp3|mp4|pdf|png|svg|tar|tiff?|txt|webm|webp|woff2?|xlsx?|zip)(?:$|\?)/i;

export function normalizeTarget(value) {
  const url = new URL(value);
  if (!/^https?:$/.test(url.protocol)) {
    throw new Error("Target must use http:// or https://.");
  }
  if (url.username || url.password) {
    throw new Error("Targets containing embedded usernames or passwords are not accepted.");
  }
  url.hash = "";
  return url;
}

function finding(id, severity, title, evidence, location, remediation) {
  const url = new URL(location);
  const fingerprintInput = `${id}|${url.origin}${url.pathname}`;
  const fingerprint = createHash("sha256").update(fingerprintInput).digest("hex").slice(0, 16);
  return { id, severity, title, evidence, location, remediation, fingerprint };
}

function headerValue(headers, name) {
  return headers.get(name)?.trim() || "";
}

async function readBody(response, maxBytes) {
  if (!response.body) return { text: "", truncated: false };

  const reader = response.body.getReader();
  const chunks = [];
  let total = 0;
  let truncated = false;
  try {
    while (true) {
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

async function fetchBounded(startUrl, options) {
  let current = new URL(startUrl);
  const chain = [];

  for (let hop = 0; hop <= options.maxRedirects; hop += 1) {
    assertInScope(current.href, options.scope);
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), options.timeoutMs);
    let response;
    try {
      response = await fetch(current, {
        method: "GET",
        redirect: "manual",
        signal: controller.signal,
        headers: {
          accept: "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.1",
          "user-agent": "SentinelScan/0.1 (authorized security posture audit)",
        },
      });
    } finally {
      clearTimeout(timeout);
    }

    const status = response.status;
    const location = response.headers.get("location");
    if (status >= 300 && status < 400 && location) {
      const next = new URL(location, current);
      assertInScope(next.href, options.scope);
      chain.push({ from: current.href, to: next.href, status });
      current = next;
      continue;
    }

    const body = await readBody(response, options.maxResponseBytes);
    return {
      requestedUrl: startUrl,
      finalUrl: current.href,
      response,
      body,
      chain,
    };
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
    const formUrl = formAction ? new URL(formAction, pageUrl) : new URL(pageUrl);
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
  return {
    url: pageUrl,
    path: new URL(pageUrl).pathname,
    links: links.length,
    sameOriginLinks: links.filter((link) => link.origin === rootOrigin).length,
    forms: forms.length,
    passwordForms: formBlocks.filter((form) => /type\s*=\s*["']?password\b/i.test(form)).length,
    scripts: scripts.length,
    externalScripts: externalScripts.length,
  };
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

async function checkWellKnownPaths(rootUrl, options, findings) {
  const paths = ["/robots.txt", "/sitemap.xml", "/.well-known/security.txt", "/.git/HEAD"];
  for (const path of paths) {
    const url = new URL(path, rootUrl);
    let result;
    try {
      result = await fetchBounded(url.href, options);
    } catch {
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
    }
  }
}

export async function scan(target, overrides = {}) {
  const root = normalizeTarget(target);
  const scope = normalizeScope(overrides.scope || { allowedOrigins: [root.origin] });
  assertInScope(root.href, scope);
  const options = { ...DEFAULTS, ...overrides, scope };
  const startedAt = new Date().toISOString();
  const findings = [];
  const pages = [];
  const inventoryPages = [];
  const queued = new Set([root.href]);
  const visited = new Set();
  let firstResult;

  while (queued.size && pages.length < options.maxPages) {
    const nextUrl = queued.values().next().value;
    queued.delete(nextUrl);
    if (visited.has(nextUrl)) continue;
    visited.add(nextUrl);

    let result;
    try {
      result = await fetchBounded(nextUrl, options);
    } catch (error) {
      findings.push(finding(
        "request-failed",
        "info",
        "Request could not be completed",
        error.name === "AbortError" ? "The request timed out." : error.message,
        nextUrl,
        "Verify the target is available and repeat the scan with an appropriate timeout.",
      ));
      continue;
    }

    if (!firstResult) firstResult = result;
    const contentType = headerValue(result.response.headers, "content-type");
    const isHtml = /(?:text\/html|application\/xhtml\+xml)/i.test(contentType) || !contentType;
    pages.push({
      requestedUrl: nextUrl,
      finalUrl: result.finalUrl,
      status: result.response.status,
      contentType,
      bytesRead: new TextEncoder().encode(result.body.text).byteLength,
      truncated: result.body.truncated,
    });

    if (pages.length === 1) {
      addHeaderFindings(findings, result.response.headers, result.finalUrl);
      addCookieFindings(findings, result.response.headers, result.finalUrl);
      if (root.protocol === "http:") {
        if (new URL(result.finalUrl).protocol === "https:") {
          findings.push(finding(
            "http-redirects-to-https",
            "info",
            "HTTP redirects to HTTPS",
            "The target redirected the initial HTTP request to HTTPS.",
            root.href,
            "Keep the redirect and consider HSTS after confirming all subdomains are HTTPS-ready.",
          ));
        } else {
          findings.push(finding(
            "site-served-over-http",
            "high",
            "Site is served over HTTP",
            "The initial target and final response are not encrypted with HTTPS.",
            result.finalUrl,
            "Deploy HTTPS and redirect every HTTP request to the HTTPS origin.",
          ));
        }
      }
      if (new URL(result.finalUrl).protocol === "https:" && !headerValue(result.response.headers, "strict-transport-security")) {
        findings.push(finding(
          "missing-hsts",
          "low",
          "Strict transport security is missing",
          "The HTTPS response does not include Strict-Transport-Security.",
          result.finalUrl,
          "After confirming all relevant subdomains support HTTPS, add a carefully staged HSTS policy.",
        ));
      }
    }

    if (isHtml) {
      addHtmlFindings(findings, result.body.text, result.finalUrl, root.origin);
      inventoryPages.push(extractPageInventory(result.body.text, result.finalUrl, root.origin));
      if (!result.body.truncated) {
        for (const link of extractLinks(result.body.text, result.finalUrl)) {
          if (link.origin !== root.origin || SKIPPED_EXTENSIONS.test(link.pathname + link.search)) continue;
          if (visited.size + queued.size >= options.maxPages) break;
          queued.add(link.href);
        }
      }
    }

    if (queued.size && options.delayMs > 0) await new Promise((resolve) => setTimeout(resolve, options.delayMs));
  }

  await checkWellKnownPaths(root, options, findings);
  const finalFindings = uniqueFindings(findings);
  const attackPaths = buildAttackPaths(finalFindings);
  const risk = calculateRisk(finalFindings, attackPaths);
  const counts = finalFindings.reduce((result, item) => {
    result[item.severity] = (result[item.severity] || 0) + 1;
    return result;
  }, {});

  const limits = { ...options };
  delete limits.scope;
  return {
    scanner: { name: "SentinelScan", version: "0.3.0", mode: "bounded-passive" },
    target: root.href,
    scope: { name: scope.name, allowedOrigins: scope.allowedOrigins },
    startedAt,
    finishedAt: new Date().toISOString(),
    limits,
    summary: { pagesScanned: pages.length, findings: finalFindings.length, bySeverity: counts, attackPaths: attackPaths.length, riskScore: risk.score, riskGrade: risk.grade },
    pages,
    inventory: {
      pages: inventoryPages,
      totals: {
        links: inventoryPages.reduce((total, page) => total + page.links, 0),
        forms: inventoryPages.reduce((total, page) => total + page.forms, 0),
        passwordForms: inventoryPages.reduce((total, page) => total + page.passwordForms, 0),
        scripts: inventoryPages.reduce((total, page) => total + page.scripts, 0),
        externalScripts: inventoryPages.reduce((total, page) => total + page.externalScripts, 0),
      },
    },
    findings: finalFindings,
    attackPaths,
    risk,
    notes: [
      "This report contains observations from safe GET requests only.",
      "A finding is a lead for review, not proof of exploitability.",
      firstResult?.finalUrl ? `Initial request resolved to ${firstResult.finalUrl}.` : "The initial request did not complete.",
    ],
  };
}

export { DEFAULTS };
