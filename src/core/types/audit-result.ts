import type { AuthorizationMode, IntensityProfile } from './authorization.js';
import type { ConsentArtifact } from './consent.js';
import type { Target } from './target.js';
import type { ScannerResult } from './scanner.js';
import type { Finding } from './finding.js';
import type { Insight } from './insight.js';
import type { MeasuredScoreSummary } from './score.js';
import type { RatingSummary } from './rating.js';
import type { ReportCounters } from './report-counters.js';
import type { AuditStatus } from './audit-context.js';

/**
 * The immutable persisted output of a run. Deliberately separate from
 * AuditContext — AuditContext is mutable runtime state, AuditResult is the
 * frozen record written to storage and rendered into reports.
 */
export interface AuditResult {
  readonly id: string;
  readonly target: Target;
  readonly authorizationMode: AuthorizationMode;
  readonly profile: IntensityProfile;
  readonly consentArtifact?: ConsentArtifact;
  readonly status: AuditStatus;
  readonly startedAt: string;
  readonly finishedAt: string;
  readonly isWordPress: boolean;
  readonly scannerResults: readonly ScannerResult[];
  readonly findings: readonly Finding[];
  readonly insights: readonly Insight[];
  /** Qualitative Security/Maintenance/Infrastructure/Overall levels — see rating-engine.ts. */
  readonly ratings?: RatingSummary;
  /** Numeric scores backed by a real external measurement (currently just Performance/Lighthouse) — see scoring-engine.ts. */
  readonly measuredScores?: MeasuredScoreSummary;
  readonly counters?: ReportCounters;
  /** e.g. "PageSpeed enrichment unavailable" — surfaced in the report's limitations section. */
  readonly limitations: string[];
}
