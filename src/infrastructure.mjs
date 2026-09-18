import { lookup, resolveCaa, resolveTxt } from "node:dns/promises";
import tls from "node:tls";

const COMMON_DKIM_SELECTORS = ["default", "google", "selector1", "selector2", "k1"];

function isIpAddress(host) {
  return /^\d{1,3}(?:\.\d{1,3}){3}$/.test(host) || host.includes(":");
}

function isLocalHost(host) {
  return host === "localhost" || host.endsWith(".localhost") || host === "127.0.0.1" || host === "::1" || isIpAddress(host);
}

function flattenTxt(records) {
  return records.map((record) => record.join(""));
}

function queryTls(url, timeoutMs) {
  return new Promise((resolve) => {
    const socket = tls.connect({
      host: url.hostname,
      port: Number(url.port || 443),
      servername: url.hostname,
      rejectUnauthorized: false,
    });
    let settled = false;
    const finish = (value) => {
      if (settled) return;
      settled = true;
      socket.destroy();
      resolve(value);
    };
    const timeout = setTimeout(() => finish({ error: "TLS connection timed out." }), timeoutMs);
    socket.once("secureConnect", () => {
      clearTimeout(timeout);
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
      clearTimeout(timeout);
      finish({ error: error.message });
    });
  });
}

async function queryDns(host) {
  const result = { addresses: [], error: "" };
  try {
    result.addresses = (await lookup(host, { all: true, verbatim: true })).map((entry) => entry.address);
  } catch (error) {
    result.error = error.message;
  }
  return result;
}

async function queryEmailDns(domain, selectors) {
  const email = { domain, spf: [], dmarc: [], caa: [], dkim: {} };
  try { email.spf = flattenTxt(await resolveTxt(domain)).filter((item) => /^v=spf1\b/i.test(item)); } catch { /* no record */ }
  try { email.dmarc = flattenTxt(await resolveTxt(`_dmarc.${domain}`)).filter((item) => /^v=dmarc1\b/i.test(item)); } catch { /* no record */ }
  try { email.caa = (await resolveCaa(domain)).map((record) => ({ flags: record.critical || 0, tag: record.issue || record.tag || "", value: record.value || "" })); } catch { /* no record */ }
  for (const selector of selectors) {
    try {
      const records = flattenTxt(await resolveTxt(`${selector}._domainkey.${domain}`));
      if (records.length) email.dkim[selector] = records;
    } catch { /* selector is optional */ }
  }
  return email;
}

async function queryCertificateTransparency(host, timeoutMs) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const query = encodeURIComponent(`%25.${host}`);
    const response = await fetch(`https://crt.sh/?q=${query}&output=json`, {
      headers: { accept: "application/json", "user-agent": "SentinelScan/0.5 (authorized security posture audit)" },
      signal: controller.signal,
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
    return { certificates: [], error: error.name === "AbortError" ? "Certificate Transparency lookup timed out." : error.message };
  } finally {
    clearTimeout(timeout);
  }
}

export async function inspectInfrastructure(target, options = {}) {
  const url = new URL(target);
  const metadata = { host: url.hostname, dns: null, tls: null, email: null, certificateTransparency: null };
  const findings = [];
  if (isLocalHost(url.hostname)) return { metadata, findings, skipped: "Local or IP target; public DNS metadata checks were skipped." };

  metadata.dns = await queryDns(url.hostname);
  if (metadata.dns.error) {
    findings.push({ id: "dns-resolution-failed", severity: "medium", title: "DNS resolution failed", evidence: metadata.dns.error, location: target, remediation: "Verify that the target hostname has a stable public DNS record." });
  }

  if (url.protocol === "https:") {
    metadata.tls = await queryTls(url, options.timeoutMs || 8_000);
    if (metadata.tls.error) {
      findings.push({ id: "tls-connection-failed", severity: "medium", title: "TLS connection could not be inspected", evidence: metadata.tls.error, location: target, remediation: "Confirm that the public HTTPS service is available and presents a certificate for the requested host." });
    } else if (!metadata.tls.authorized) {
      findings.push({ id: "tls-certificate-invalid", severity: "high", title: "TLS certificate is not trusted by Node", evidence: metadata.tls.authorizationError || "The certificate chain was not authorized.", location: target, remediation: "Install a complete certificate chain from a trusted issuer and verify hostname coverage." });
    }
  }

  const domain = options.emailDomain || url.hostname;
  metadata.email = await queryEmailDns(domain, options.dkimSelectors || COMMON_DKIM_SELECTORS);
  if (!metadata.email.spf.length) findings.push({ id: "missing-spf", severity: "low", title: "SPF record was not observed", evidence: `No v=spf1 TXT record was found for ${domain}.`, location: target, remediation: "Publish an SPF policy if this domain sends email, and keep it within provider lookup limits." });
  if (!metadata.email.dmarc.length) findings.push({ id: "missing-dmarc", severity: "low", title: "DMARC record was not observed", evidence: `No v=DMARC1 TXT record was found for _dmarc.${domain}.`, location: target, remediation: "Publish a monitored DMARC policy for the domain's email-sending identity." });
  if (!metadata.email.caa.length) findings.push({ id: "missing-caa", severity: "info", title: "CAA record was not observed", evidence: `No CAA record was found for ${domain}.`, location: target, remediation: "Consider restricting certificate issuance with a CAA policy when operationally appropriate." });

  if (options.certificateTransparency) {
    metadata.certificateTransparency = await queryCertificateTransparency(url.hostname, options.timeoutMs || 8_000);
    if (!metadata.certificateTransparency.certificates.length && !metadata.certificateTransparency.error) {
      findings.push({ id: "ct-no-certificates", severity: "info", title: "No Certificate Transparency entries were returned", evidence: `crt.sh returned no entries for ${url.hostname}.`, location: target, remediation: "Confirm the hostname and review your certificate inventory through the issuing CA if this is unexpected." });
    }
  }
  return { metadata, findings };
}

export { COMMON_DKIM_SELECTORS };
