import { assertInScope } from "./scope.mjs";
import { ScanBudgetError, normalizeTarget, redactText, redactUrl } from "./scanner.mjs";
import { fetchWithNetworkPolicy } from "./network-policy.mjs";

export class BrowserModeError extends Error {
  constructor(message, code = "BROWSER_MODE_UNAVAILABLE") {
    super(message);
    this.name = "BrowserModeError";
    this.code = code;
  }
}

async function loadPlaywright() {
  for (const packageName of ["playwright", "playwright-core"]) {
    try {
      return await import(packageName);
    } catch {
      // Browser support is intentionally optional for the dependency-free core.
    }
  }
  throw new BrowserModeError("Rendered mode requires the optional Playwright package. Install playwright and retry.");
}

function abortError(signal) {
  return signal?.reason || new DOMException("The scan was canceled.", "AbortError");
}

function assertBrowserUrl(value, scope) {
  const url = normalizeTarget(value);
  if (!/^https?:$/.test(url.protocol)) throw new BrowserModeError(`Browser request blocked because its scheme is not HTTP(S): ${url.protocol}`, "BROWSER_POLICY_BLOCKED");
  assertInScope(url.href, scope);
  return url;
}

function requestIsAllowed(request, scope) {
  const url = assertBrowserUrl(request.url(), scope);
  const method = request.method().toUpperCase();
  const resourceType = request.resourceType();
  if (!["GET", "HEAD"].includes(method)) throw new BrowserModeError(`Browser request blocked because method ${method} is not allowed.`, "BROWSER_POLICY_BLOCKED");
  if (["websocket", "eventsource", "manifest"].includes(resourceType) || /^wss?:$/i.test(url.protocol)) throw new BrowserModeError("Browser request blocked because WebSocket, EventSource, and manifest traffic are not allowed.", "BROWSER_POLICY_BLOCKED");
  return url;
}

function boundedTimeout(options, deadlineAt) {
  const remaining = deadlineAt === undefined ? options.timeoutMs : deadlineAt - Date.now();
  if (remaining <= 0) throw new ScanBudgetError("Maximum scan duration reached.");
  return Math.max(1, Math.min(options.timeoutMs, remaining));
}

export async function readBoundedBody(response, maxBytes, signal) {
  if (!response.body) return { bytes: new Uint8Array(), truncated: false };
  const reader = response.body.getReader();
  const chunks = [];
  let total = 0;
  let truncated = false;
  const abortReader = () => { void reader.cancel(signal.reason).catch(() => {}); };
  if (signal?.aborted) {
    await reader.cancel(signal.reason).catch(() => {});
    reader.releaseLock();
    throw abortError(signal);
  }
  signal?.addEventListener("abort", abortReader, { once: true });
  try {
    while (true) {
      if (signal?.aborted) throw abortError(signal);
      const { done, value } = await reader.read();
      if (signal?.aborted) throw abortError(signal);
      if (done) break;
      const remaining = maxBytes - total;
      if (value.byteLength > remaining) {
        if (remaining > 0) chunks.push(value.slice(0, remaining));
        total += Math.max(0, remaining);
        truncated = true;
        await reader.cancel().catch(() => {});
        break;
      }
      chunks.push(value);
      total += value.byteLength;
    }
  } finally {
    signal?.removeEventListener("abort", abortReader);
    reader.releaseLock();
  }
  const bytes = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return { bytes, truncated };
}

function browserRequestHeaders(requestHeaders, options, url) {
  const headers = Object.fromEntries(Object.entries(requestHeaders).map(([name, value]) => [name.toLowerCase(), value]));
  for (const name of ["host", "content-length", "connection", "transfer-encoding", "accept-encoding"]) delete headers[name];
  if (options.authHeaderOrigins?.includes(url.origin)) {
    for (const [name, value] of Object.entries(options.authHeaders || {})) headers[name.toLowerCase()] = value;
  }
  return headers;
}

function responseHeaderRecord(response, truncated) {
  const blocked = new Set(["connection", "keep-alive", "proxy-authenticate", "proxy-authorization", "te", "trailer", "transfer-encoding", "upgrade", "set-cookie"]);
  if (truncated) for (const name of ["content-length", "content-range", "content-md5", "etag"]) blocked.add(name);
  const headers = Object.fromEntries([...response.headers].filter(([name]) => !blocked.has(name.toLowerCase())));
  return headers;
}

function parseCookie(cookie, responseUrl) {
  const [pair, ...attributes] = cookie.split(";");
  const separator = pair.indexOf("=");
  if (separator <= 0) return null;
  const name = pair.slice(0, separator).trim();
  const value = pair.slice(separator + 1).trim();
  if (!name || /[\s;,]/.test(name)) return null;
  const parsedUrl = new URL(responseUrl);
  const result = { name, value, url: `${parsedUrl.origin}${parsedUrl.pathname}` };
  let maxAge;
  for (const attribute of attributes) {
    const [rawName, ...rawValue] = attribute.trim().split("=");
    const key = rawName.toLowerCase();
    const setting = rawValue.join("=").trim();
    if (key === "domain" && setting) {
      const domain = setting.replace(/^\./, "").toLowerCase();
      if (parsedUrl.hostname !== domain && !parsedUrl.hostname.endsWith(`.${domain}`)) return null;
      result.domain = domain;
      delete result.url;
    } else if (key === "path" && setting.startsWith("/")) result.path = setting;
    else if (key === "expires") {
      const expires = Date.parse(setting);
      if (Number.isFinite(expires)) result.expires = Math.floor(expires / 1_000);
    } else if (key === "max-age" && /^-?\d+$/.test(setting)) maxAge = Number(setting);
    else if (key === "secure") result.secure = true;
    else if (key === "httponly") result.httpOnly = true;
    else if (key === "samesite" && ["lax", "strict", "none"].includes(setting.toLowerCase())) {
      result.sameSite = setting[0].toUpperCase() + setting.slice(1).toLowerCase();
    }
  }
  if (!result.url) result.path ||= "/";
  if (maxAge !== undefined) result.expires = Math.floor(Date.now() / 1_000) + maxAge;
  if (result.sameSite === "None" && !result.secure) return null;
  return result;
}

async function applyResponseCookies(context, response, url) {
  const cookies = response.headers.getSetCookie?.() || [response.headers.get("set-cookie")].filter(Boolean);
  const parsed = cookies.map((cookie) => parseCookie(cookie, url)).filter(Boolean);
  for (const cookie of parsed) await context.addCookies([cookie]).catch(() => {});
}

export async function fetchRendered(target, options, controls = {}) {
  boundedTimeout(options, controls.deadlineAt);
  const playwright = await loadPlaywright();
  const browserType = playwright.chromium;
  if (!browserType) throw new BrowserModeError("The installed Playwright package does not expose Chromium.");
  const browser = await browserType.launch({ headless: true, timeout: boundedTimeout(options, controls.deadlineAt) });
  const context = await browser.newContext({ serviceWorkers: "block", acceptDownloads: false });
  const page = await context.newPage();
  const requests = [];
  const responseRecords = [];
  const routedResponses = new WeakMap();
  const stopController = new AbortController();
  const abortFromCaller = () => stopController.abort(abortError(options.signal));
  if (options.signal?.aborted) abortFromCaller();
  else options.signal?.addEventListener("abort", abortFromCaller, { once: true });
  const deadlineTimer = controls.deadlineAt === undefined ? undefined : setTimeout(
    () => stopController.abort(new ScanBudgetError("Maximum scan duration reached.")),
    Math.max(1, controls.deadlineAt - Date.now()),
  );
  const closeOnStop = () => { void context.close().catch(() => {}); };
  stopController.signal.addEventListener("abort", closeOnStop, { once: true });
  let policyError;
  let gate = Promise.resolve();

  const withRequestGate = async (operation) => {
    const previous = gate;
    let release;
    gate = new Promise((resolve) => { release = resolve; });
    await previous;
    try {
      if (stopController.signal.aborted) throw stopController.signal.reason;
      if (controls.deadlineAt !== undefined && Date.now() >= controls.deadlineAt) throw new ScanBudgetError("Maximum scan duration reached.");
      await controls.pacer?.wait();
      if (stopController.signal.aborted) throw stopController.signal.reason;
      if (controls.consumeRequest && !controls.consumeRequest()) throw new ScanBudgetError("Maximum request budget reached.");
      return await operation();
    } finally {
      controls.pacer?.done();
      release();
    }
  };

  const routeHandler = async (route) => {
    try {
      const request = route.request();
      const url = requestIsAllowed(request, options.scope);
      await withRequestGate(async () => {
        const timeoutMs = boundedTimeout(options, controls.deadlineAt);
        const controller = new AbortController();
        const abortFromStop = () => controller.abort(stopController.signal.reason);
        if (stopController.signal.aborted) abortFromStop();
        else stopController.signal.addEventListener("abort", abortFromStop, { once: true });
        const timeout = setTimeout(() => controller.abort(new DOMException("Rendered request timed out.", "AbortError")), timeoutMs);
        try {
          const requestHeaders = await request.allHeaders();
          const response = await fetchWithNetworkPolicy(url, {
            method: request.method(),
            headers: browserRequestHeaders(requestHeaders, options, url),
            allowPrivateNetwork: options.allowPrivateNetwork,
            signal: controller.signal,
            timeoutMs,
          });
          if (controller.signal.aborted) throw abortError(controller.signal);
          const encoding = response.headers.get("content-encoding");
          if (encoding && !/^identity$/i.test(encoding)) {
            await response.body?.cancel().catch(() => {});
            throw new BrowserModeError("Rendered response used compression despite the scanner's identity-encoding request.", "BROWSER_RESPONSE_ENCODING_BLOCKED");
          }
          const body = await readBoundedBody(response, options.maxResponseBytes, controller.signal);
          await applyResponseCookies(context, response, url.href);
          routedResponses.set(request, {
            truncated: body.truncated,
            bytesRead: body.bytes.byteLength,
            setCookies: response.headers.getSetCookie?.() || [response.headers.get("set-cookie")].filter(Boolean),
          });
          await route.fulfill({ status: response.status, headers: responseHeaderRecord(response, body.truncated), body: Buffer.from(body.bytes) });
        } finally {
          clearTimeout(timeout);
          stopController.signal.removeEventListener("abort", abortFromStop);
        }
      });
    } catch (error) {
      if (error instanceof ScanBudgetError || stopController.signal.aborted || ["BROWSER_POLICY_BLOCKED", "BROWSER_RESPONSE_ENCODING_BLOCKED", "NETWORK_POLICY_BLOCKED"].includes(error.code)) {
        policyError ||= stopController.signal.aborted ? stopController.signal.reason : error;
      }
      await route.abort("blockedbyclient").catch(() => {});
    }
  };

  await context.route("**/*", routeHandler);
  page.on("response", (response) => {
    const request = response.request();
    responseRecords.push({ request, url: response.url(), status: response.status(), headers: response.headers(), ...(routedResponses.get(request) || {}) });
  });
  page.on("requestfailed", (request) => {
    requests.push({ url: redactUrl(request.url()), status: null, elapsedMs: null, error: redactText(request.failure()?.errorText || "Browser request failed.") });
  });
  page.on("download", (download) => { download.cancel().catch(() => {}); });

  try {
    assertBrowserUrl(target, options.scope);
    let response;
    try {
      response = await page.goto(target, { waitUntil: "domcontentloaded", timeout: boundedTimeout(options, controls.deadlineAt) });
    } catch (error) {
      if (stopController.signal.aborted) throw stopController.signal.reason;
      if (policyError) throw policyError;
      throw error;
    }
    if (stopController.signal.aborted) throw stopController.signal.reason;
    if (policyError) throw policyError;
    if (!response) throw new BrowserModeError("Browser navigation returned no HTTP response.", "BROWSER_NAVIGATION_FAILED");
    let contentTimer;
    let text;
    try {
      text = await Promise.race([
      page.content(),
      new Promise((_, reject) => { contentTimer = setTimeout(() => reject(new BrowserModeError("Rendered document exceeded its content timeout.", "BROWSER_NAVIGATION_FAILED")), boundedTimeout(options, controls.deadlineAt)); }),
      ]);
    } catch (error) {
      if (stopController.signal.aborted) throw stopController.signal.reason;
      throw error;
    } finally {
      clearTimeout(contentTimer);
    }
    const bytes = new TextEncoder().encode(text);
    const domTruncated = bytes.byteLength > options.maxResponseBytes;
    const bodyBytes = domTruncated ? bytes.slice(0, options.maxResponseBytes) : bytes;
    const bodyText = new TextDecoder().decode(bodyBytes);
    const finalRoute = [...responseRecords].reverse().find((entry) => entry.request.isNavigationRequest() && entry.url === response.url()) || {};
    const truncated = domTruncated || finalRoute.truncated === true;
    const navigationRecords = responseRecords.filter((entry) => entry.request.isNavigationRequest());
    const chain = navigationRecords.filter((entry) => entry.status >= 300 && entry.status < 400).map((entry) => ({ from: redactUrl(entry.url), to: entry.headers.location ? redactUrl(new URL(entry.headers.location, entry.url).href) : redactUrl(entry.url), status: entry.status }));
    const requestEntries = responseRecords.map((entry) => ({ url: redactUrl(entry.url), status: entry.status, elapsedMs: null, bytesRead: entry.bytesRead ?? null, ...(entry.truncated ? { truncated: true } : {}), ...(entry.status >= 300 && entry.status < 400 && entry.headers.location ? { redirectedTo: redactUrl(new URL(entry.headers.location, entry.url).href) } : {}) }));
    const finalHeaders = new Headers(response.headers());
    for (const cookie of finalRoute.setCookies || []) finalHeaders.append("set-cookie", cookie);
    return {
      requestedUrl: redactUrl(target),
      finalUrl: redactUrl(page.url()),
      response: new Response(bodyText, { status: response.status(), headers: finalHeaders }),
      body: { text: bodyText, truncated, bytesRead: bodyBytes.byteLength },
      chain,
      requests: [...requestEntries, ...requests],
    };
  } finally {
    clearTimeout(deadlineTimer);
    options.signal?.removeEventListener("abort", abortFromCaller);
    stopController.signal.removeEventListener("abort", closeOnStop);
    await context.close().catch(() => {});
    await browser.close().catch(() => {});
  }
}
