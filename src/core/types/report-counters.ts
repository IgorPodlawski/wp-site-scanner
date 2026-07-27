import type { FindingSeverity } from './finding.js';

/**
 * Report-wide counts derived from the final Finding list — computed once
 * (finding-engine.ts's calculateReportCounters) so the report and any
 * insight built on top of it always agree on the same numbers.
 */
export interface ReportCounters {
  componentsWithVulnerabilities: number;
  /** Deduplicated (CVE -> WPScan id -> normalized title) across every component, not just within one. */
  uniqueVulnerabilityCount: number;
  outdatedComponentCount: number;
  findingsBySeverity: Record<FindingSeverity, number>;
}
