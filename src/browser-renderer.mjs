import { assertInScope } from "./scope.mjs";
import { ScanBudgetError } from "./scanner.mjs";
import { resolveAllowedAddresses } from "./network-policy.mjs";

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
  const url = new URL(value);
  if (!/^https?:$/.test(url.protocol)) throw new BrowserModeError(`Browser request blocked because its scheme is not HTTP(S): ${url.protocol}`, "BROWSER_POLICY_BLOCKED");
  assertInScope(url.href, scope);
  if ([...url.searchParams.keys()].some((key) => /(?:authorization|api[_-]?key|client[_-]?secret|password|passwd|secret|session|signature|sig|token|access[_-]?token|refresh[_-]?token)/i.test(key))) {
    throw new BrowserModeError("Browser request blocked because its URL contains credential-shaped query data.", "BROWSER_POLICY_BLOCKED");
  }
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

export async function fetchRendered(target, options, controls = {}) {
  const playwright = await loadPlaywright();
  const browserType = playwright.chromium;
  if (!browserType) throw new BrowserModeError("The installed Playwright package does not expose Chromium.");
  const browser = await browserType.launch({ headless: true });
  const context = await browser.newContext({ serviceWorkers: "block", acceptDownloads: false });
  const page = await context.newPage();
  const requests = [];
  const responseRecords = [];
  let policyError;
  let gate = Promise.resolve();

  const withRequestGate = async (operation) => {
    const previous = gate;
    let release;
    gate = new Promise((resolve) => { release = resolve; });
    await previous;
    try {
      if (options.signal?.aborted) throw abortError(options.signal);
      if (controls.deadlineAt !== undefined && Date.now() >= controls.deadlineAt) throw new ScanBudgetError("Maximum scan duration reached.");
      await controls.pacer?.wait();
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
      await resolveAllowedAddresses(url.hostname, { allowPrivateNetwork: options.allowPrivateNetwork, signal: options.signal, timeoutMs: options.timeoutMs });
      await withRequestGate(async () => {
        const headers = { ...request.headers() };
        if (options.authHeaderOrigins?.includes(url.origin)) Object.assign(headers, options.authHeaders);
        await route.continue({ headers });
      });
    } catch (error) {
      policyError ||= error;
      await route.abort("blockedbyclient").catch(() => {});
    }
  };

  await context.route("**/*", routeHandler);
  page.on("response", (response) => {
    const request = response.request();
    responseRecords.push({ response, request, url: response.url(), status: response.status(), headers: response.headers() });
  });
  page.on("requestfailed", (request) => {
    requests.push({ url: request.url(), status: null, elapsedMs: null, error: request.failure()?.errorText || "Browser request failed." });
  });
  page.on("download", (download) => { download.cancel().catch(() => {}); });

  try {
    assertBrowserUrl(target, options.scope);
    const response = await page.goto(target, { waitUntil: "domcontentloaded", timeout: boundedTimeout(options, controls.deadlineAt) });
    if (policyError) throw policyError;
    if (!response) throw new BrowserModeError("Browser navigation returned no HTTP response.", "BROWSER_NAVIGATION_FAILED");
    const text = await page.content();
    const bytes = new TextEncoder().encode(text);
    const truncated = bytes.byteLength > options.maxResponseBytes;
    const bodyBytes = truncated ? bytes.slice(0, options.maxResponseBytes) : bytes;
    const bodyText = new TextDecoder().decode(bodyBytes);
    const navigationRecords = responseRecords.filter((entry) => entry.request.isNavigationRequest());
    const chain = navigationRecords.filter((entry) => entry.status >= 300 && entry.status < 400).map((entry) => ({ from: entry.url, to: entry.headers.location ? new URL(entry.headers.location, entry.url).href : entry.url, status: entry.status }));
    const requestEntries = responseRecords.map((entry) => ({ url: entry.url, status: entry.status, elapsedMs: null, ...(entry.status >= 300 && entry.status < 400 && entry.headers.location ? { redirectedTo: new URL(entry.headers.location, entry.url).href } : {}) }));
    return {
      requestedUrl: target,
      finalUrl: page.url(),
      response: new Response(bodyText, { status: response.status(), headers: response.headers() }),
      body: { text: bodyText, truncated, bytesRead: bodyBytes.byteLength },
      chain,
      requests: [...requestEntries, ...requests],
    };
  } finally {
    await context.close().catch(() => {});
    await browser.close().catch(() => {});
  }
}
