import { Resolver } from "node:dns/promises";
import { isIP } from "node:net";
import tls from "node:tls";
import { fetchWithNetworkPolicy, isPrivateAddress } from "./network-policy.mjs";

const COMMON_DKIM_SELECTORS = ["default", "google", "selector1", "selector2", "k1"];
const INFRASTRUCTURE_BUDGET_CODE = "SCAN_BUDGET_EXHAUSTED";

function controlError(message) {
  const error = new Error(message);
  error.code = INFRASTRUCTURE_BUDGET_CODE;
  return error;
}

function abortError(signal) {
  return signal?.reason || new DOMException("The scan was canceled.", "AbortError");
}

function assertActive(options) {
  if (options.signal?.aborted) throw abortError(options.signal);
  if (options.remainingMs && options.remainingMs() <= 0) throw controlError("Maximum scan duration reached.");
}

async function runExternal(options, operation, cancel) {
  assertActive(options);
  await options.beforeRequest?.();
  let timer;
  let onAbort;
  const remaining = options.remainingMs?.();
  try {
    assertActive(options);
    const operationPromise = Promise.resolve().then(operation);
    const waits = [operationPromise];
    const operationTimeout = Math.min(
      Number.isFinite(options.timeoutMs) && options.timeoutMs > 0 ? options.timeoutMs : 8_000,
      Number.isFinite(remaining) ? remaining : Number.POSITIVE_INFINITY,
    );
    if (Number.isFinite(operationTimeout)) {
      waits.push(new Promise((_, reject) => {
        timer = setTimeout(() => {
          cancel?.();
          reject(new Error("Infrastructure operation timed out."));
        }, Math.max(1, operationTimeout));
      }));
    }
    if (options.signal) {
      const abortPromise = new Promise((_, reject) => {
        onAbort = () => {
          cancel?.();
          reject(abortError(options.signal));
        };
        if (options.signal.aborted) onAbort();
        else options.signal.addEventListener("abort", onAbort, { once: true });
      });
      waits.push(abortPromise);
    }
    return await Promise.race(waits);
  } finally {
    clearTimeout(timer);
    if (onAbort) options.signal?.removeEventListener("abort", onAbort);
    options.afterRequest?.();
  }
}

function isIpAddress(host) {
  return /^\d{1,3}(?:\.\d{1,3}){3}$/.test(host) || host.includes(":");
}

function isLocalHost(host) {
  return host === "localhost" || host.endsWith(".localhost") || host === "127.0.0.1" || host === "::1" || isIpAddress(host);
}

function flattenTxt(records) {
  return records.map((record) => record.join(""));
}

async function runDns(options, operation) {
  const resolver = new Resolver();
  return runExternal(options, () => operation(resolver), () => resolver.cancel());
}

async function optionalDns(options, operation) {
  try {
    return { records: await runDns(options, operation), error: "" };
  } catch (error) {
    if (error.code === INFRASTRUCTURE_BUDGET_CODE || error.name === "AbortError") throw error;
    if (["ENODATA", "ENOTFOUND"].includes(error.code)) return { records: [], error: "" };
    return { records: [], error: error.message };
  }
}

function queryTls(url, timeoutMs, signal, resolvedAddress) {
  return new Promise((resolve, reject) => {
    if (signal?.aborted) {
      reject(abortError(signal));
      return;
    }
    const socket = tls.connect({
      host: resolvedAddress || url.hostname,
      port: Number(url.port || 443),
      servername: url.hostname,
      lookup: resolvedAddress ? (_hostname, _options, callback) => callback(null, resolvedAddress, isIP(resolvedAddress)) : undefined,
      rejectUnauthorized: false,
    });
    let settled = false;
    const finish = (value) => {
      if (settled) return;
      settled = true;
      clearTimeout(timeout);
      signal?.removeEventListener("abort", abort);
      socket.destroy();
      resolve(value);
    };
    const abort = () => {
      if (settled) return;
      settled = true;
      clearTimeout(timeout);
      socket.destroy();
      reject(abortError(signal));
    };
    const timeout = setTimeout(() => finish({ error: "TLS connection timed out." }), timeoutMs);
    signal?.addEventListener("abort", abort, { once: true });
    socket.once("secureConnect", () => {
      const certificate = socket.getPeerCertificate();
      finish({
        authorized: socket.authorized,
        authorizationError: socket.authorizationError || "",
        protocol: socket.getProtocol() || "",
        cipher: socket.getCipher()?.name || "",
        validFrom: certificate.valid_from || "",
        validTo: certificate.valid_to || "",
        subject: certificate.subject?.CN || "",
        issuer: certificate.issuer?.O || certificate.issuer?.CN || "",
      });
    });
    socket.once("error", (error) => {
      finish({ error: error.message });
    });
  });
}

async function queryDns(host, options) {
  const result = { addresses: [], error: "" };
  try {
    result.addresses = await runDns(options, async (resolver) => {
      const results = await Promise.allSettled([resolver.resolve4(host), resolver.resolve6(host)]);
      const addresses = [];
      const errors = [];
      for (const entry of results) {
        if (entry.status === "fulfilled") addresses.push(...entry.value);
        else if (!entry.reason || !["ENODATA", "ENOTFOUND"].includes(entry.reason.code)) errors.push(entry.reason);
      }
      if (addresses.length) return [...new Set(addresses)];
      if (errors.length) throw errors[0];
      throw results.find((entry) => entry.status === "rejected")?.reason || new Error(`No DNS addresses were found for ${host}.`);
    });
  } catch (error) {
    if (error.code === INFRASTRUCTURE_BUDGET_CODE || error.name === "AbortError") throw error;
    result.error = error.message;
  }
  return result;
}

async function queryEmailDns(domain, selectors, options) {
  const email = { domain, spf: [], dmarc: [], caa: [], dkim: {}, errors: {} };
  const spf = await optionalDns(options, (resolver) => resolver.resolveTxt(domain));
  email.spf = flattenTxt(spf.records).filter((item) => /^v=spf1\b/i.test(item));
  if (spf.error) email.errors.spf = spf.error;
  const dmarc = await optionalDns(options, (resolver) => resolver.resolveTxt(`_dmarc.${domain}`));
  email.dmarc = flattenTxt(dmarc.records).filter((item) => /^v=dmarc1\b/i.test(item));
  if (dmarc.error) email.errors.dmarc = dmarc.error;
  for (const selector of selectors) {
    const result = await optionalDns(options, (resolver) => resolver.resolveTxt(`${selector}._domainkey.${domain}`));
    const records = flattenTxt(result.records);
    if (records.length) email.dkim[selector] = records;
    if (result.error) email.errors[`dkim:${selector}`] = result.error;
  }
  return email;
}

async function queryCaa(host, options) {
  const result = await optionalDns(options, (resolver) => resolver.resolveCaa(host));
  const records = [];
  for (const record of result.records) {
    for (const tag of ["issue", "issuewild", "iodef"]) {
      if (record[tag]) records.push({ flags: record.critical || 0, tag, value: record[tag] });
    }
  }
  return { host, records, error: result.error };
}

async function queryCertificateTransparency(host, timeoutMs, signal) {
  const controller = new AbortController();
  const abortParent = () => controller.abort(abortError(signal));
  const timeout = setTimeout(() => controller.abort(new DOMException("Certificate Transparency lookup timed out.", "AbortError")), timeoutMs);
  signal?.addEventListener("abort", abortParent, { once: true });
  try {
    const endpoint = new URL("https://crt.sh/");
    endpoint.searchParams.set("q", `%.${host}`);
    endpoint.searchParams.set("output", "json");
    const response = await fetchWithNetworkPolicy(endpoint, {
      headers: { accept: "application/json", "user-agent": "SentinelScan/0.5 (authorized security posture audit)" },
      signal: controller.signal,
      timeoutMs,
      allowPrivateNetwork: false,
    });
    if (!response.ok) return { error: `Certificate Transparency returned HTTP ${response.status}.`, certificates: [] };
    const contentLength = Number(response.headers.get("content-length") || 0);
    if (contentLength > 4_000_000) return { error: "Certificate Transparency response exceeded the 4 MB safety limit.", certificates: [] };
    const reader = response.body?.getReader();
    const chunks = [];
    let size = 0;
    if (reader) {
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        size += value.byteLength;
        if (size > 4_000_000) {
          await reader.cancel();
          return { error: "Certificate Transparency response exceeded the 4 MB safety limit.", certificates: [] };
        }
        chunks.push(value);
      }
    }
    const bytes = new Uint8Array(chunks.reduce((total, chunk) => total + chunk.byteLength, 0));
    let offset = 0;
    for (const chunk of chunks) {
      bytes.set(chunk, offset);
      offset += chunk.byteLength;
    }
    const data = JSON.parse(new TextDecoder().decode(bytes));
    const rows = Array.isArray(data) ? data : [];
    return {
      certificates: rows.slice(0, 1000).map((row) => ({
        id: row.id,
        issuer: row.issuer_name || "",
        names: String(row.name_value || "").split(/\r?\n/).filter(Boolean).slice(0, 20),
        notBefore: row.not_before || "",
        notAfter: row.not_after || "",
      })),
      truncated: rows.length > 1000,
      error: "",
    };
  } catch (error) {
    if (signal?.aborted) throw abortError(signal);
    return { certificates: [], error: error.name === "AbortError" ? "Certificate Transparency lookup timed out." : error.message };
  } finally {
    clearTimeout(timeout);
    signal?.removeEventListener("abort", abortParent);
  }
}

export async function inspectInfrastructure(target, options = {}) {
  const url = new URL(target);
  const metadata = { host: url.hostname, dns: null, tls: null, email: null, certificateTransparency: null };
  const findings = [];
  if (isLocalHost(url.hostname)) return { metadata, findings, skipped: "Local or IP target; public DNS metadata checks were skipped." };

  metadata.dns = await queryDns(url.hostname, options);
  if (metadata.dns.error) {
    findings.push({ id: "dns-resolution-failed", severity: "medium", title: "DNS resolution failed", evidence: metadata.dns.error, location: target, remediation: "Verify that the target hostname has a stable public DNS record." });
    return { metadata, findings, skipped: "DNS resolution failed; TLS and public metadata checks were skipped." };
  }

  if (!options.allowPrivateNetwork && metadata.dns.addresses.some((address) => isPrivateAddress(address))) {
    return { metadata, findings, skipped: "Network policy blocked a non-public DNS address." };
  }

  if (url.protocol === "https:") {
    metadata.tls = await runExternal(options, () => queryTls(url, Math.min(options.timeoutMs || 8_000, options.remainingMs?.() || options.timeoutMs || 8_000), options.signal, metadata.dns.addresses[0]));
    if (metadata.tls.error) {
      findings.push({ id: "tls-connection-failed", severity: "medium", title: "TLS connection could not be inspected", evidence: metadata.tls.error, location: target, remediation: "Confirm that the public HTTPS service is available and presents a certificate for the requested host." });
    } else if (!metadata.tls.authorized) {
      findings.push({ id: "tls-certificate-invalid", severity: "high", title: "TLS certificate is not trusted by Node", evidence: metadata.tls.authorizationError || "The certificate chain was not authorized.", location: target, remediation: "Install a complete certificate chain from a trusted issuer and verify hostname coverage." });
    }
  }

  const domain = options.emailDomain || url.hostname;
  metadata.email = await queryEmailDns(domain, options.dkimSelectors || COMMON_DKIM_SELECTORS, options);
  const caa = await queryCaa(url.hostname, options);
  metadata.email.caaDomain = caa.host;
  metadata.email.caa = caa.records;
  if (caa.error) metadata.email.errors.caa = caa.error;
  if (!metadata.email.spf.length && !metadata.email.errors.spf) findings.push({ id: "missing-spf", severity: "low", title: "SPF record was not observed", evidence: `No v=spf1 TXT record was found for ${domain}.`, location: target, remediation: "Publish an SPF policy if this domain sends email, and keep it within provider lookup limits." });
  if (!metadata.email.dmarc.length && !metadata.email.errors.dmarc) findings.push({ id: "missing-dmarc", severity: "low", title: "DMARC record was not observed", evidence: `No v=DMARC1 TXT record was found for _dmarc.${domain}.`, location: target, remediation: "Publish a monitored DMARC policy for the domain's email-sending identity." });
  if (!metadata.email.caa.length && !metadata.email.errors.caa) findings.push({ id: "missing-caa", severity: "info", title: "CAA record was not observed", evidence: `No CAA record was found for ${url.hostname}.`, location: target, remediation: "Consider restricting certificate issuance with a CAA policy when operationally appropriate." });

  if (options.certificateTransparency) {
    metadata.certificateTransparency = await runExternal(options, () => queryCertificateTransparency(url.hostname, Math.min(options.timeoutMs || 8_000, options.remainingMs?.() || options.timeoutMs || 8_000), options.signal));
    if (!metadata.certificateTransparency.certificates.length && !metadata.certificateTransparency.error) {
      findings.push({ id: "ct-no-certificates", severity: "info", title: "No Certificate Transparency entries were returned", evidence: `crt.sh returned no entries for ${url.hostname}.`, location: target, remediation: "Confirm the hostname and review your certificate inventory through the issuing CA if this is unexpected." });
    }
  }
  return { metadata, findings };
}

export { COMMON_DKIM_SELECTORS };
