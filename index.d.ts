export type Severity = "info" | "low" | "medium" | "high";
export type FindingStatus = "observed" | "candidate";
export type TriageState = "open" | "suppressed";
export type ValidationArtifact = "scope" | "config" | "suppressions" | "report" | "checkpoint";

export interface Scope {
  name?: string;
  allowedOrigins: string[];
  includePaths?: string[];
  excludePaths?: string[];
  notes?: string[];
}

export interface Suppression {
  fingerprint: string;
  reason: string;
  expiresAt: string;
  owner?: string;
}

export interface FindingTriage {
  state: TriageState;
  owner?: string;
  reason?: string;
  expiresAt?: string;
  suppressionExpired?: boolean;
}

export interface Finding {
  id: string;
  severity: Severity;
  title: string;
  evidence: string;
  location: string;
  remediation: string;
  fingerprint: string;
  category: string;
  confidence: string;
  confidenceScore: number;
  status: FindingStatus;
  observedAt: string;
  triage?: FindingTriage;
}

export interface ScanLimits {
  maxPages: number;
  maxRedirects: number;
  maxResponseBytes: number;
  timeoutMs: number;
  delayMs: number;
  maxResources: number;
  maxRequests: number;
  maxElapsedMs: number;
  checkInfrastructure: boolean;
  certificateTransparency: boolean;
  allowPrivateNetwork: boolean;
  rendered: boolean;
}

export interface ScanProgress {
  phase: string;
  target: string;
  pagesScanned: number;
  resourcesScanned: number;
  requestsMade: number;
  elapsedMs: number;
  url?: string;
  kind?: string;
  status?: number;
  error?: string;
}

export interface ExitPolicy {
  failOnSeverity: Severity | null;
  failOnBaseline: "never" | "new" | "changed" | "regressed";
  requireBaseline: boolean;
  failOnIncomplete: boolean;
  failed: boolean;
  reasons: string[];
  matchedFindings: Array<Pick<Finding, "id" | "fingerprint" | "severity" | "location">>;
  baseline: { status: string; new: number; changed: number; resolved: number } | null;
  coverage: { complete: boolean; termination: string };
}

export interface ReportIntegrity {
  algorithm: "sha256";
  contentHash: string;
}

export interface ScanIdentity {
  algorithm: "sha256";
  value: string;
}

export interface ScanCoverage {
  complete: boolean;
  termination: string;
  pages: number;
  resources: number;
  requests: number;
  deferred: number;
}

export interface Comparison {
  baselineTarget: string;
  baselineFinishedAt?: string;
  newFindings: Finding[];
  resolvedFindings: Finding[];
  unchangedFindings: Finding[];
  changedFindings: Array<{ previous: Finding; current: Finding }>;
  suppressedFindings: Finding[];
  suppressedInsteadOfResolved: Finding[];
  summary: { new: number; resolved: number; unchanged: number; changed: number; suppressed: number; baselineSuppressed: number; riskDelta: number; status: string };
}

export interface ScanReport {
  schemaVersion: 2;
  scanner: { name: string; version: string; mode: "bounded-passive" | "bounded-rendered" };
  target: string;
  scope: Scope;
  startedAt: string;
  finishedAt: string;
  limits: ScanLimits;
  scanIdentity: ScanIdentity;
  coverage: ScanCoverage;
  integrity: ReportIntegrity;
  summary: Record<string, unknown> & { findings: number; actionableFindings: number; suppressedFindings: number };
  pages: unknown[];
  resources: unknown[];
  requests: unknown[];
  infrastructure: Record<string, unknown>;
  inventory: Record<string, unknown>;
  findings: Finding[];
  suppressions: Suppression[];
  attackPaths: unknown[];
  risk: Record<string, unknown>;
  comparison?: Comparison;
  exitPolicy?: ExitPolicy;
  notes: string[];
}

export interface ScanOptions {
  confirmAuthorized: true;
  scope?: Scope;
  maxPages?: number;
  maxRedirects?: number;
  maxResponseBytes?: number;
  timeoutMs?: number;
  delayMs?: number;
  maxResources?: number;
  maxRequests?: number;
  maxElapsedMs?: number;
  checkInfrastructure?: boolean;
  certificateTransparency?: boolean;
  allowPrivateNetwork?: boolean;
  rendered?: boolean;
  confirmRendered?: boolean;
  emailDomain?: string;
  dkimSelectors?: string[];
  authHeaders?: Record<string, string>;
  authHeaderOrigins?: string[];
  suppressions?: Suppression[];
  checkpointPath?: string;
  resume?: Record<string, unknown>;
  signal?: AbortSignal;
  onProgress?: (progress: ScanProgress) => void;
}

export interface ValidationResult {
  kind: ValidationArtifact;
  warnings?: string[];
  [key: string]: unknown;
}

export declare const DEFAULTS: Readonly<ScanLimits>;
export declare class ScanBudgetError extends Error { code: "SCAN_BUDGET_EXHAUSTED"; }
export declare function scan(target: string, options: ScanOptions): Promise<ScanReport>;
export declare function normalizeTarget(value: string): URL;
export declare function redactUrl(value: string): string;
export declare function normalizeScope(value: Scope): Scope;
export declare function assertInScope(value: string, scope: Scope): void;
export declare function normalizeAuthHeaders(headers?: Record<string, string>): Record<string, string>;
export declare function normalizeAuthHeaderOrigins(value: string[] | undefined, rootOrigin: string): string[];
export declare function normalizeEmailDomain(value?: string): string | undefined;
export declare function compareReports(current: ScanReport, baseline: ScanReport): Comparison;
export declare function toSarif(report: ScanReport, options?: { includeSuppressed?: boolean }): Record<string, unknown>;
export declare function toHtml(report: ScanReport): string;

export interface DetectorDescriptor {
  id: string;
  phase: string;
  severity: Severity;
  title: string;
  category: string;
  remediation: string;
  safetyRationale: string;
  confidence: string;
  confidenceScore: number;
  status: FindingStatus;
}
export declare const DETECTOR_CATALOG: readonly DetectorDescriptor[];
export declare function getDetector(id: string): DetectorDescriptor | undefined;
export declare function validateDetectorCatalog(): true;
export declare function normalizeSuppressions(value?: Suppression[]): Suppression[];
export declare function applyTriage(findings: Finding[], suppressions?: Suppression[], now?: number): Finding[];
export declare function actionableFindings(findings: Finding[]): Finding[];
export declare function isSuppressed(finding: Finding): boolean;
export declare function triageCounts(findings: Finding[]): { actionableFindings: number; suppressedFindings: number };
export declare function normalizeExitPolicy(value?: Partial<Pick<ExitPolicy, "failOnSeverity" | "failOnBaseline" | "requireBaseline" | "failOnIncomplete">>): Omit<ExitPolicy, "failed" | "reasons" | "matchedFindings" | "baseline" | "coverage">;
export declare function evaluateExitPolicy(report: ScanReport, policy?: Partial<ExitPolicy>): ExitPolicy;
export declare function canonicalJson(value: unknown): string;
export declare function sha256(value: unknown): string;
export declare function addIntegrity<T extends Record<string, unknown>>(value: T, field?: string): T & { integrity: { algorithm: "sha256"; [key: string]: string } };
export declare function verifyIntegrity(value: unknown, field?: string): boolean;
export declare function buildScanIdentity(value: Record<string, unknown>): ScanIdentity;
export declare class ValidationError extends Error { code: "INVALID_ARTIFACT"; path: string; }
export declare function validateArtifact(kind: ValidationArtifact, value: unknown): ValidationResult;
export declare function validateConfig(value: unknown): ValidationResult;
