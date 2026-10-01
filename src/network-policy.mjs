import { lookup, Resolver } from "node:dns/promises";
import { isIP } from "node:net";
import { Readable } from "node:stream";
import http from "node:http";
import https from "node:https";

export class NetworkPolicyError extends Error {
  constructor(message) {
    super(message);
    this.name = "NetworkPolicyError";
    this.code = "NETWORK_POLICY_BLOCKED";
  }
}

function ipv4ToInteger(address) {
  const parts = address.split(".").map(Number);
  if (parts.length !== 4 || parts.some((part) => !Number.isInteger(part) || part < 0 || part > 255)) return null;
  return (((parts[0] * 256 + parts[1]) * 256 + parts[2]) * 256 + parts[3]) >>> 0;
}

function ipv4InRange(address, network, prefix) {
  const value = ipv4ToInteger(address);
  const base = ipv4ToInteger(network);
  if (value === null || base === null) return false;
  const mask = prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0;
  return (value & mask) === (base & mask);
}

function parseIpv6(address) {
  const normalized = address.toLowerCase().replace(/^\[|\]$/g, "");
  const pieces = normalized.split("::");
  if (pieces.length > 2) return null;
  const expand = (part) => {
    if (!part) return [];
    const result = [];
    for (const segment of part.split(":")) {
      if (segment.includes(".")) {
        const value = ipv4ToInteger(segment);
        if (value === null) return null;
        result.push((value >>> 16).toString(16), (value & 0xffff).toString(16));
      } else if (/^[0-9a-f]{1,4}$/.test(segment)) {
        result.push(segment);
      } else {
        return null;
      }
    }
    return result;
  };
  const left = expand(pieces[0]);
  const right = expand(pieces[1] || "");
  if (!left || !right) return null;
  const parts = pieces.length === 2 ? [...left, ...Array(8 - left.length - right.length).fill("0"), ...right] : left;
  if (parts.length !== 8) return null;
  return parts.reduce((value, part) => (value << 16n) | BigInt(`0x${part}`), 0n);
}

function ipv6InRange(address, network, prefix) {
  const value = parseIpv6(address);
  const base = parseIpv6(network);
  if (value === null || base === null) return false;
  const shift = 128n - BigInt(prefix);
  return (value >> shift) === (base >> shift);
}

function isNonPublicIpv4(address) {
  return [
    ["0.0.0.0", 8],
    ["10.0.0.0", 8],
    ["100.64.0.0", 10],
    ["127.0.0.0", 8],
    ["169.254.0.0", 16],
    ["172.16.0.0", 12],
    ["192.0.0.0", 24],
    ["192.0.2.0", 24],
    ["192.168.0.0", 16],
    ["192.31.196.0", 24],
    ["192.52.193.0", 24],
    ["192.88.99.0", 24],
    ["192.175.48.0", 24],
    ["198.18.0.0", 15],
    ["198.51.100.0", 24],
    ["203.0.113.0", 24],
    ["224.0.0.0", 4],
    ["240.0.0.0", 4],
  ].some(([network, prefix]) => ipv4InRange(address, network, prefix));
}

function isNonPublicIpv6(address) {
  const value = parseIpv6(address);
  if (value === null) return true;
  if ((value >> 32n) === 0xffffn) {
    const mapped = Number(value & 0xffffffffn);
    const ipv4 = `${mapped >>> 24}.${(mapped >>> 16) & 255}.${(mapped >>> 8) & 255}.${mapped & 255}`;
    return isNonPublicIpv4(ipv4);
  }
  if (ipv6InRange(address, "2002::", 16)) {
    const embedded = Number((value >> 80n) & 0xffffffffn);
    const ipv4 = `${embedded >>> 24}.${(embedded >>> 16) & 255}.${(embedded >>> 8) & 255}.${embedded & 255}`;
    if (isNonPublicIpv4(ipv4)) return true;
  }
  if ([
    ["::", 128],
    ["::1", 128],
    ["fc00::", 7],
    ["fe80::", 10],
    ["fec0::", 10],
    ["ff00::", 8],
    ["2001:db8::", 32],
    ["2001::", 23],
    ["2001:10::", 28],
    ["2001:2::", 48],
    ["2001:20::", 28],
  ].some(([network, prefix]) => ipv6InRange(address, network, prefix))) return true;
  return !ipv6InRange(address, "2000::", 3);
}

export function isPrivateAddress(address) {
  const normalized = String(address).replace(/^\[|\]$/g, "").split("%")[0];
  const version = isIP(normalized);
  return version === 4 ? isNonPublicIpv4(normalized) : version === 6 ? isNonPublicIpv6(normalized) : true;
}

function isPrivateHostname(hostname) {
  const host = hostname.toLowerCase().replace(/\.$/, "");
  return host === "localhost" || host.endsWith(".localhost") || host.endsWith(".local") || host.endsWith(".internal") || host.endsWith(".localdomain") || host.endsWith(".lan") || host.endsWith(".test") || host.endsWith(".invalid") || host.endsWith(".example") || host === "home.arpa" || host.endsWith(".home.arpa");
}

function abortError(signal) {
  return signal?.reason || new DOMException("The request was canceled.", "AbortError");
}

async function resolveAll(hostname, signal, timeoutMs, allowPrivateNetwork) {
  const family = isIP(hostname);
  if (family) return [{ address: hostname, family }];
  if (allowPrivateNetwork && /^(?:localhost|.+\.localhost)$/i.test(hostname)) {
    const operation = lookup(hostname, { all: true, verbatim: true });
    if (!signal && !(timeoutMs > 0)) return operation;
    let timer;
    let onAbort;
    try {
      const waits = [operation];
      if (signal) waits.push(new Promise((_, reject) => {
        onAbort = () => reject(abortError(signal));
        if (signal.aborted) reject(abortError(signal));
        else signal.addEventListener("abort", onAbort, { once: true });
      }));
      if (timeoutMs > 0) waits.push(new Promise((_, reject) => { timer = setTimeout(() => reject(new DOMException("DNS resolution timed out.", "TimeoutError")), timeoutMs); }));
      return await Promise.race(waits);
    } finally {
      clearTimeout(timer);
      if (onAbort) signal.removeEventListener("abort", onAbort);
    }
  }

  if (signal?.aborted) throw abortError(signal);
  const resolver = new Resolver();
  let timer;
  let onAbort;
  try {
    const operation = Promise.allSettled([resolver.resolve4(hostname), resolver.resolve6(hostname)]).then((results) => {
      const addresses = [];
      const errors = [];
      for (let index = 0; index < results.length; index += 1) {
        const result = results[index];
        if (result.status === "fulfilled") {
          const version = index === 0 ? 4 : 6;
          for (const address of result.value) addresses.push({ address, family: version });
        } else if (!result.reason || !["ENODATA", "ENOTFOUND"].includes(result.reason.code)) {
          errors.push(result.reason);
        }
      }
      if (addresses.length) return addresses;
      if (errors.length) throw errors[0];
      const error = new Error(`No DNS addresses were found for ${hostname}.`);
      error.code = "ENODATA";
      throw error;
    });
    const waits = [operation];
    if (signal) waits.push(new Promise((_, reject) => {
      onAbort = () => {
        resolver.cancel();
        reject(abortError(signal));
      };
      if (signal.aborted) onAbort();
      else signal.addEventListener("abort", onAbort, { once: true });
    }));
    if (timeoutMs > 0) waits.push(new Promise((_, reject) => {
      timer = setTimeout(() => {
        resolver.cancel();
        reject(new DOMException("DNS resolution timed out.", "TimeoutError"));
      }, timeoutMs);
    }));
    return await Promise.race(waits);
  } finally {
    clearTimeout(timer);
    if (onAbort) signal.removeEventListener("abort", onAbort);
    resolver.cancel();
  }
}

export async function resolveAllowedAddresses(hostname, { allowPrivateNetwork = false, signal, timeoutMs } = {}) {
  const normalized = String(hostname).replace(/^\[|\]$/g, "").toLowerCase();
  if (!allowPrivateNetwork && isPrivateHostname(normalized)) throw new NetworkPolicyError(`Private or reserved hostname blocked by network policy: ${hostname}`);
  const dnsTimeoutMs = Number.isFinite(timeoutMs) && timeoutMs > 0 ? timeoutMs : 8_000;
  const addresses = await resolveAll(normalized, signal, dnsTimeoutMs, allowPrivateNetwork);
  if (!addresses.length) throw new NetworkPolicyError(`No address was returned for ${hostname}.`);
  if (!allowPrivateNetwork && addresses.some((entry) => isPrivateAddress(entry.address))) {
    throw new NetworkPolicyError(`Private or non-public address resolution blocked for ${hostname}.`);
  }
  return addresses;
}

export async function resolveAllowedAddress(hostname, options = {}) {
  return (await resolveAllowedAddresses(hostname, options))[0];
}

function responseHeaders(response) {
  const headers = new Headers();
  for (const [name, value] of Object.entries(response.headers)) {
    if (value === undefined) continue;
    if (Array.isArray(value)) {
      for (const item of value) headers.append(name, String(item));
    } else {
      headers.set(name, String(value));
    }
  }
  return headers;
}

function containsCredentialShapedUrlData(url) {
  if (url.username || url.password) return true;
  const sensitiveKey = /^(?:authorization|api[_-]?key|client[_-]?secret|password|passwd|secret|session|signature|sig|token|access[_-]?token|refresh[_-]?token)$/i;
  const sensitiveAssignment = /\b(?:authorization|api[_-]?key|client[_-]?secret|password|passwd|secret|session|signature|sig|token|access[_-]?token|refresh[_-]?token)\b\s*[=:]\s*[^&\s,;]+/i;
  if (/%(?![0-9a-f]{2})/i.test(url.search)) throw new NetworkPolicyError("Malformed encoded URL data is blocked by the network policy.");
  for (const [key, value] of url.searchParams) {
    let decoded = value.replace(/%(?![0-9a-f]{2})/gi, "");
    try {
      decoded = decodeURIComponent(decoded);
    } catch {}
    if (sensitiveKey.test(key) || sensitiveAssignment.test(decoded) || /(?:[?&]|^)\w*(?:token|secret|password|api[_-]?key)\s*=/i.test(decoded)) return true;
  }
  return false;
}

function isRetryableConnectionError(error) {
  return ["EADDRNOTAVAIL", "ECONNREFUSED", "ECONNRESET", "EHOSTUNREACH", "ENETUNREACH", "ETIMEDOUT"].includes(error?.code);
}

function requestOnce(url, address, options) {
  const transport = url.protocol === "https:" ? https : http;
  const hostname = url.hostname.replace(/^\[|\]$/g, "");
  const headers = { ...(options.headers || {}) };
  headers["accept-encoding"] = "identity";
  const bodyless = new Set([204, 205, 304]);

  return new Promise((resolve, reject) => {
    let request;
    let settled = false;
    const onAbort = () => {
      request?.destroy(abortError(options.signal));
      finish(reject, abortError(options.signal));
    };
    const finish = (callback, value) => {
      if (settled) return;
      settled = true;
      options.signal?.removeEventListener("abort", onAbort);
      callback(value);
    };
    try {
      request = transport.request({
        protocol: url.protocol,
        hostname,
        port: url.port || undefined,
        path: `${url.pathname || "/"}${url.search}`,
        method: options.method || "GET",
        headers,
        ...(url.protocol === "https:" && !isIP(hostname) ? { servername: hostname } : {}),
        lookup: (_hostname, _options, callback) => callback(null, address.address, address.family),
      }, (response) => {
        try {
          const body = bodyless.has(response.statusCode) ? null : Readable.toWeb(response);
          finish(resolve, new Response(body, { status: response.statusCode, statusText: response.statusMessage, headers: responseHeaders(response) }));
        } catch (error) {
          response.destroy(error);
          finish(reject, error);
        }
      });
      request.once("error", (error) => finish(reject, error));
      options.signal?.addEventListener("abort", onAbort, { once: true });
      if (options.signal?.aborted) return onAbort();
      request.end();
    } catch (error) {
      finish(reject, error);
    }
  });
}

export async function fetchWithNetworkPolicy(target, options = {}) {
  const url = new URL(target);
  if (!/^https?:$/.test(url.protocol)) throw new NetworkPolicyError("Only HTTP(S) requests are supported by the network policy.");
  const method = String(options.method || "GET").toUpperCase();
  if (!["GET", "HEAD"].includes(method)) throw new NetworkPolicyError("Only GET and HEAD requests are supported by the network policy.");
  if (containsCredentialShapedUrlData(url)) throw new NetworkPolicyError("Credential-shaped URL data is blocked by the network policy.");
  const addresses = await resolveAllowedAddresses(url.hostname, options);
  let lastError;
  for (const address of addresses) {
    try {
      return await requestOnce(url, address, { ...options, method });
    } catch (error) {
      lastError = error;
      if (options.signal?.aborted || !isRetryableConnectionError(error)) throw error;
    }
  }
  throw lastError || new Error(`Unable to connect to ${url.hostname}.`);
}
