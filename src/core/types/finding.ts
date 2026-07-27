export type FindingCategory = 'security' | 'maintenance' | 'performance' | 'seo' | 'infrastructure';

export type FindingSeverity = 'info' | 'low' | 'medium' | 'high' | 'critical';

export type FindingConfidence = 'inferred' | 'corroborated' | 'confirmed';

export type SourceLayer = 1 | 2 | 3 | 'third-party';

export type BusinessImpact = 'none' | 'weak' | 'medium' | 'strong';

export interface FindingEvidence {
  descriptionKey: string;
  params?: Record<string, string | number>;
  /** Raw observation backing this evidence line (e.g. header value). JSON/debug output only. */
  raw?: unknown;
}

/**
 * Present only on a merged component (WordPress core/plugin/theme) finding.
 * `vulnerabilitySeverities` is the resolved severity of each *applicable*,
 * deduplicated vulnerability — the finding's own `severity` is the max of
 * these, and scoring-engine.ts uses the full list (not just the max) for its
 * per-component aggregation. Empty when the component is outdated but has
 * no known vulnerabilities.
 */
export interface ComponentFindingInfo {
  kind: 'core' | 'plugin' | 'theme';
  slug: string;
  isOutdated: boolean;
  vulnerabilitySeverities: FindingSeverity[];
}

export interface Finding {
  id: string;
  category: FindingCategory;
  severity: FindingSeverity;
  confidence: FindingConfidence;
  sourceLayer: SourceLayer;
  businessImpact: BusinessImpact;
  recommendationKey: string;
  recommendationParams?: Record<string, string | number>;
  evidence: FindingEvidence[];
  component?: ComponentFindingInfo;
}

export type FindingInput = Finding;

/**
 * The only supported way to construct a Finding. Severity is taken as given
 * — it must already be resolved (from CVSS/WPScan data for a vulnerability,
 * or a fixed severity for non-vulnerability findings) before reaching here.
 * Confidence never adjusts severity; it only ever affects scoring weight and
 * report wording, both handled elsewhere (scoring-engine.ts, report
 * rendering).
 */
export function createFinding(input: FindingInput): Finding {
  return { ...input };
}
