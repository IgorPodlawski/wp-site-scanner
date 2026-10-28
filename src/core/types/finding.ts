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
 * `confirmed` mirrors the same "version confirmed AND applicable" check that
 * selects a vulnerability's confirmed/potential evidence wording — kept here
 * too so rating-engine.ts's Security rule can read it without re-deriving it
 * from evidence description keys.
 *
 * `knownExploited` is PHP-specific (from `php-vulnerability-client.ts`'s
 * cross-reference against the CISA KEV catalog of confirmed-actively-
 * exploited CVEs) — always `false` for WordPress core/plugin/theme
 * vulnerabilities, which have no such cross-reference. rating-engine.ts's
 * Security rule treats a `knownExploited` vulnerability as urgent-eligible
 * even when `confirmed` is false, since PHP's version can only ever come
 * from a single header source (see `ComponentFindingInfo.kind === 'php'`
 * below) and so is realistically never `confirmed` on its own — CISA's own
 * confirmation of active exploitation is a stronger signal than our version
 * confidence either way.
 */
export interface ComponentVulnerabilityInfo {
  severity: FindingSeverity;
  confirmed: boolean;
  knownExploited: boolean;
}

/**
 * Present only on a merged component (WordPress core/plugin/theme/PHP)
 * finding. `vulnerabilities` is each *applicable*, deduplicated
 * vulnerability's resolved severity + confirmed-applicable flag — the
 * finding's own `severity` is derived from these (max, with escalation —
 * see finding-engine.ts), and rating-engine.ts's Security rule reads the raw
 * list directly rather than the escalated badge. Empty when the component is
 * outdated but has no known vulnerabilities.
 *
 * `kind: 'php'` is the one non-WordPress case — the PHP runtime underneath
 * WordPress, not a WordPress component itself. Reuses this exact shape
 * (merged finding, same vulnerability list, same rating integration)
 * because the "one finding per thing, severity from its own vulnerability
 * data" model applies identically; `slug` is an internal key (`'php'`),
 * never rendered, same convention as core's `'wordpress-core'`.
 */
export interface ComponentFindingInfo {
  kind: 'core' | 'plugin' | 'theme' | 'php';
  slug: string;
  isOutdated: boolean;
  vulnerabilities: ComponentVulnerabilityInfo[];
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
