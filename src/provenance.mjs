import { createHash } from "node:crypto";

function canonicalize(value) {
  if (Array.isArray(value)) return value.map(canonicalize);
  if (value && typeof value === "object") {
    return Object.fromEntries(Object.keys(value).sort().filter((key) => value[key] !== undefined).map((key) => [key, canonicalize(value[key])]));
  }
  return value;
}

export function canonicalJson(value) {
  return JSON.stringify(canonicalize(value));
}

export function sha256(value) {
  const input = typeof value === "string" ? value : canonicalJson(value);
  return createHash("sha256").update(input).digest("hex");
}

function withoutIntegrity(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) return value;
  const copy = { ...value };
  delete copy.integrity;
  return copy;
}

export function addIntegrity(value, field = "contentHash") {
  const payload = withoutIntegrity(value);
  return {
    ...payload,
    integrity: {
      algorithm: "sha256",
      [field]: sha256(payload),
    },
  };
}

export function verifyIntegrity(value, field = "contentHash") {
  if (!value?.integrity || value.integrity.algorithm !== "sha256" || typeof value.integrity[field] !== "string") return false;
  return value.integrity[field] === sha256(withoutIntegrity(value));
}

export function buildScanIdentity({ scanner, scope, limits, detectorCatalog, attackPathRules }) {
  const identity = {
    scanner,
    scope,
    limits,
    detectors: (detectorCatalog || []).map(({ id, severity, category, confidenceScore, status }) => ({ id, severity, category, confidenceScore, status })),
    attackPathRules: attackPathRules || [],
  };
  return { algorithm: "sha256", value: sha256(identity) };
}
