import type { AuthorizationMode, IntensityProfile } from './authorization.js';
import type { ConsentArtifact } from './consent.js';
import type { Target } from './target.js';
import type { ScannerResult } from './scanner.js';
import type { Finding } from './finding.js';
import type { Insight } from './insight.js';
export type AuditStatus = 'completed' | 'partial' | 'failed';

/**
 * Mutable runtime state passed through the pipeline. Grows only through
 * controlled, append-style writes made by the orchestrator between stages.
 * No scanner mutates another scanner's data; no free-form mutation. Each
 * field is write-once per producing stage — see DefaultAuditContext.
 */
export interface AuditContext {
  readonly target: Target;
  readonly authorizationMode: AuthorizationMode;
  readonly profile: IntensityProfile;
  readonly consentArtifact?: ConsentArtifact;
  readonly startedAt: string;

  addScannerResult(result: ScannerResult): void;
  getScannerResults(): readonly ScannerResult[];

  /** HttpResponse shape is owned by core/http — kept opaque here to avoid a cross-module type dependency. */
  setHttpResponse(response: unknown): void;
  getHttpResponse(): unknown | undefined;

  setDetectedWordPress(isWordPress: boolean): void;
  isWordPress(): boolean | undefined;

  setEnrichment(provider: string, data: unknown): void;
  getEnrichment(provider: string): unknown | undefined;

  addFinding(finding: Finding): void;
  getFindings(): readonly Finding[];

  setInsights(insights: readonly Insight[]): void;
  getInsights(): readonly Insight[] | undefined;
}

export interface AuditContextInit {
  target: Target;
  authorizationMode: AuthorizationMode;
  profile: IntensityProfile;
  consentArtifact?: ConsentArtifact;
  startedAt: string;
}

/**
 * Reference implementation of AuditContext. Write-once fields throw if set
 * a second time — the mechanical enforcement of "controlled writes only".
 * Append-only collections (scanner results, findings) simply accumulate.
 */
export class DefaultAuditContext implements AuditContext {
  readonly target: Target;
  readonly authorizationMode: AuthorizationMode;
  readonly profile: IntensityProfile;
  readonly consentArtifact?: ConsentArtifact;
  readonly startedAt: string;

  private scannerResults: ScannerResult[] = [];
  private httpResponse: unknown | undefined;
  private wordPressDetected: boolean | undefined;
  private enrichments = new Map<string, unknown>();
  private findings: Finding[] = [];
  private insights: readonly Insight[] | undefined;

  constructor(init: AuditContextInit) {
    this.target = init.target;
    this.authorizationMode = init.authorizationMode;
    this.profile = init.profile;
    if (init.consentArtifact !== undefined) {
      this.consentArtifact = init.consentArtifact;
    }
    this.startedAt = init.startedAt;
  }

  addScannerResult(result: ScannerResult): void {
    this.scannerResults.push(result);
  }

  getScannerResults(): readonly ScannerResult[] {
    return this.scannerResults;
  }

  setHttpResponse(response: unknown): void {
    if (this.httpResponse !== undefined) {
      throw new Error('AuditContext.httpResponse is write-once and has already been set.');
    }
    this.httpResponse = response;
  }

  getHttpResponse(): unknown | undefined {
    return this.httpResponse;
  }

  setDetectedWordPress(isWordPress: boolean): void {
    if (this.wordPressDetected !== undefined) {
      throw new Error('AuditContext.wordPressDetected is write-once and has already been set.');
    }
    this.wordPressDetected = isWordPress;
  }

  isWordPress(): boolean | undefined {
    return this.wordPressDetected;
  }

  setEnrichment(provider: string, data: unknown): void {
    if (this.enrichments.has(provider)) {
      throw new Error(`AuditContext enrichment for "${provider}" is write-once and already set.`);
    }
    this.enrichments.set(provider, data);
  }

  getEnrichment(provider: string): unknown | undefined {
    return this.enrichments.get(provider);
  }

  addFinding(finding: Finding): void {
    this.findings.push(finding);
  }

  getFindings(): readonly Finding[] {
    return this.findings;
  }

  setInsights(insights: readonly Insight[]): void {
    if (this.insights !== undefined) {
      throw new Error('AuditContext.insights is write-once and has already been set.');
    }
    this.insights = insights;
  }

  getInsights(): readonly Insight[] | undefined {
    return this.insights;
  }
}
