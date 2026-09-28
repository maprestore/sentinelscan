const DEFAULT_CONFIDENCE = { confidence: "high", confidenceScore: 0.9, status: "observed" };

const definitions = [
  ["site-served-over-http", "transport", "high", "Site is served over HTTP", "transport", "Deploy HTTPS and redirect every HTTP request to the HTTPS origin."],
  ["http-redirects-to-https", "transport", "info", "HTTP redirects to HTTPS", "transport", "Keep the redirect and consider HSTS after confirming all subdomains are HTTPS-ready."],
  ["https-redirects-to-http", "transport", "high", "HTTPS redirects to HTTP", "transport", "Reject HTTPS-to-HTTP redirects and keep the complete navigation path encrypted."],
  ["missing-hsts", "headers", "low", "Strict transport security is missing", "transport", "After confirming all relevant subdomains support HTTPS, add a carefully staged HSTS policy."],
  ["weak-hsts-duration", "headers", "low", "Strict transport security duration is short", "transport", "Use a staged rollout, then target at least six months of HSTS coverage once every required hostname supports HTTPS."],
  ["hsts-missing-subdomains", "headers", "info", "Strict transport security does not cover subdomains", "transport", "Add includeSubDomains only after confirming every relevant subdomain is HTTPS-ready."],
  ["mixed-content-reference", "markup", "medium", "HTTPS page references HTTP content", "transport", "Serve every page resource over HTTPS or remove the dependency."],
  ["tls-certificate-invalid", "infrastructure", "high", "TLS certificate is not trusted by Node", "transport", "Install a complete certificate chain from a trusted issuer and verify hostname coverage", { confidenceScore: 0.98 }],
  ["tls-connection-failed", "infrastructure", "medium", "TLS connection could not be inspected", "transport", "Confirm that the public HTTPS service is available and presents a certificate for the requested host."],
  ["missing-content-security-policy", "headers", "low", "Missing Content-Security-Policy", "browser-policy", "Set a policy appropriate for the application and verify it does not break required functionality."],
  ["weak-content-security-policy", "headers", "medium", "Content-Security-Policy contains weak directives", "browser-policy", "Remove unsafe-inline, unsafe-eval, and broad wildcards where possible; use nonces or hashes for intentional inline code."],
  ["incomplete-content-security-policy", "headers", "low", "Content-Security-Policy is incomplete", "browser-policy", "Define an explicit default-src and script-src policy appropriate for the application."],
  ["missing-referrer-policy", "headers", "low", "Missing Referrer-Policy", "browser-policy", "Set a policy appropriate for the application and verify it does not break required functionality."],
  ["missing-permissions-policy", "headers", "low", "Missing Permissions-Policy", "browser-policy", "Set a policy appropriate for the application and verify it does not break required functionality."],
  ["missing-x-content-type-options", "headers", "low", "MIME sniffing protection is missing", "browser-policy", "Send X-Content-Type-Options: nosniff for browser-served resources."],
  ["missing-clickjacking-protection", "headers", "medium", "Clickjacking protection is missing", "browser-policy", "Set a deliberate frame policy, such as frame-ancestors 'none' or a trusted embedding origin."],
  ["obsolete-frame-policy", "headers", "low", "X-Frame-Options uses an obsolete directive", "browser-policy", "Use CSP frame-ancestors for a modern, testable framing policy."],
  ["sensitive-page-cache-policy", "headers", "low", "Sensitive-looking page lacks a restrictive cache policy", "browser-policy", "Set a deliberate cache policy for authenticated or sensitive pages and verify intermediary behavior.", { confidence: "medium", confidenceScore: 0.75, status: "candidate" }],
  ["cors-wildcard-with-credentials", "headers", "high", "CORS allows credentials with a wildcard origin", "browser-policy", "Allow only explicit trusted origins and review whether credentialed cross-origin access is required."],
  ["cross-origin-iframe-without-sandbox", "markup", "low", "Cross-origin iframe has no sandbox attribute", "browser-policy", "Add the narrowest sandbox policy compatible with the integration and explicitly review postMessage trust.", { confidenceScore: 0.95 }],
  ["external-window-missing-noopener", "markup", "low", "New window link lacks rel=noopener", "browser-policy", "Add rel=noopener, and add noreferrer only when the referrer behavior is intentionally changed."],
  ["external-script-without-sri", "markup", "low", "External script has no integrity attribute", "browser-policy", "Pin the script to a trusted version and add an integrity hash with an appropriate crossorigin value."],
  ["cookie-missing-secure", "cookies", "low", "Cookie is missing Secure", "session", "Add Secure to cookies that should only travel over HTTPS."],
  ["cookie-missing-httponly", "cookies", "low", "Cookie is missing HttpOnly", "session", "Add HttpOnly to cookies that do not need JavaScript access."],
  ["cookie-missing-samesite", "cookies", "low", "Cookie is missing SameSite", "session", "Set SameSite=Lax or SameSite=Strict unless a cross-site use case is intentional."],
  ["credential-form-over-http", "forms", "high", "Credential form submits over HTTP", "authentication", "Submit credentials only to an HTTPS endpoint and redirect HTTP traffic before the form is shown."],
  ["credential-form-cross-origin", "forms", "high", "Credential form submits to another origin", "authentication", "Confirm the destination is an explicitly trusted authentication boundary and review its scope, transport, cookies, and CSRF protections together.", { confidenceScore: 0.95 }],
  ["credential-form-uses-get", "forms", "high", "Credential form uses GET", "authentication", "Use POST over HTTPS for credential submission and confirm credentials are not accepted in query strings.", { confidenceScore: 0.99 }],
  ["potential-client-secret", "client", "high", "Potential secret-like value is visible to clients", "client-exposure", "Treat the value as exposed: revoke or rotate it, then move privileged operations behind a server-side authorization boundary.", { confidence: "medium", confidenceScore: 0.72, status: "candidate" }],
  ["client-dangerous-sink", "client", "low", "Client code contains a security-sensitive sink", "client-exposure", "Review data flow into the sink, prefer safe DOM APIs, and validate postMessage origins explicitly.", { confidence: "low", confidenceScore: 0.5, status: "candidate" }],
  ["public-source-map-reference", "client", "low", "Client code references a source map", "client-exposure", "Publish source maps only when their exposure is intentional and ensure they contain no secrets or internal source that should remain private.", { confidenceScore: 0.96 }],
  ["sensitive-data-in-json", "client", "medium", "JSON response contains sensitive-looking fields", "data-exposure", "Confirm the response is intentionally public and remove credentials, session material, and unnecessary personal data from client-visible JSON.", { confidence: "medium", confidenceScore: 0.78, status: "candidate" }],
  ["potential-open-redirect", "client", "low", "Redirect-like parameter accepts an absolute URL", "redirect", "Validate redirect destinations against an explicit allowlist and reject untrusted absolute URLs.", { confidence: "low", confidenceScore: 0.45, status: "candidate" }],
  ["client-api-endpoint", "client", "info", "Client-side API endpoint was inventoried", "application-inventory", "Review the endpoint's authentication, authorization, rate limits, and data minimization separately.", { confidenceScore: 0.98 }],
  ["exposed-git-metadata", "well-known", "high", "Git metadata is publicly readable", "disclosure", "Remove repository metadata from the web root and rotate any credentials that may have been committed."],
  ["exposed-environment-file", "well-known", "high", "Environment file is publicly readable", "disclosure", "Remove environment files from the web root, rotate any values they contained, and block the path at the server or CDN."],
  ["public-configuration-or-api-description", "well-known", "medium", "Public configuration or API description is readable", "disclosure", "Confirm the document is intentionally public, remove secrets and internal endpoints, and protect operational configuration."],
  ["robots-discloses-sensitive-path", "well-known", "info", "robots.txt names sensitive-looking paths", "disclosure", "Treat robots.txt as public. Do not rely on it to protect administrative or private paths."],
  ["technology-disclosure", "headers", "info", "Server technology is disclosed", "disclosure", "Remove or generalize unnecessary version and framework identifiers where practical."],
  ["security-contact-published", "well-known", "info", "Security contact is published", "disclosure", "Keep the contact and policy links current."],
  ["security-contact-missing", "well-known", "low", "security.txt has no Contact field", "disclosure", "Add a monitored security contact address or URL so researchers can report issues responsibly."],
  ["security-contact-expiry-invalid", "well-known", "low", "security.txt has no valid Expires field", "disclosure", "Publish a future RFC 9116 Expires timestamp and renew it before it lapses."],
  ["security-contact-expired", "well-known", "low", "security.txt has expired", "disclosure", "Renew the security.txt document with a future Expires timestamp."],
  ["dns-resolution-failed", "infrastructure", "medium", "DNS resolution failed", "infrastructure", "Verify that the target hostname has a stable public DNS record."],
  ["missing-spf", "infrastructure", "low", "SPF record was not observed", "email", "Publish an SPF policy if this domain sends email, and keep it within provider lookup limits."],
  ["missing-dmarc", "infrastructure", "low", "DMARC record was not observed", "email", "Publish a monitored DMARC policy for the domain's email-sending identity."],
  ["missing-caa", "infrastructure", "info", "CAA record was not observed", "infrastructure", "Consider restricting certificate issuance with a CAA policy when operationally appropriate."],
  ["ct-no-certificates", "infrastructure", "info", "No Certificate Transparency entries were returned", "infrastructure", "Confirm the hostname and review your certificate inventory through the issuing CA if this is unexpected."],
  ["request-failed", "operational", "info", "Request could not be completed", "availability", "Verify the target is available and repeat the scan with an appropriate timeout.", { confidenceScore: 0.98 }],
];

export const DETECTOR_CATALOG = Object.freeze(definitions.map(([id, phase, severity, title, category, remediation, profile = {}]) => Object.freeze({
  id,
  phase,
  severity,
  title,
  category,
  remediation,
  safetyRationale: "This detector observes responses, markup, metadata, or client-visible code without submitting forms or exploiting the target.",
  ...DEFAULT_CONFIDENCE,
  ...profile,
})));

export const DETECTORS_BY_ID = new Map(DETECTOR_CATALOG.map((detector) => [detector.id, detector]));

export function getDetector(id) {
  return DETECTORS_BY_ID.get(id);
}

export function validateDetectorCatalog(catalog = DETECTOR_CATALOG) {
  const ids = new Set();
  for (const detector of catalog) {
    if (!detector || typeof detector !== "object") throw new Error("Detector descriptors must be objects.");
    if (!/^[a-z0-9-]+$/.test(detector.id) || ids.has(detector.id)) throw new Error(`Detector IDs must be unique lowercase slugs: ${detector.id}`);
    if (!detector.phase || !detector.severity || !detector.title || !detector.category || !detector.remediation || !detector.safetyRationale) throw new Error(`Detector ${detector.id} is missing required metadata.`);
    if (!Number.isFinite(detector.confidenceScore) || detector.confidenceScore < 0 || detector.confidenceScore > 1) throw new Error(`Detector ${detector.id} has an invalid confidence score.`);
    ids.add(detector.id);
  }
  return true;
}

validateDetectorCatalog();
