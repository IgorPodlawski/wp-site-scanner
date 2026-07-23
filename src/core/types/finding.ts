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
}

const SEVERITY_ORDER: FindingSeverity[] = ['info', 'low', 'medium', 'high', 'critical'];

/**
 * Confidence caps severity — hard rule, not a preference. Only `confirmed`
 * may reach `critical`; `inferred` may never exceed `medium`.
 */
const CONFIDENCE_CAP: Record<FindingConfidence, FindingSeverity> = {
  inferred: 'medium',
  corroborated: 'high',
  confirmed: 'critical',
};

export function capSeverityByConfidence(
  requested: FindingSeverity,
  confidence: FindingConfidence,
): FindingSeverity {
  const cap = CONFIDENCE_CAP[confidence];
  return SEVERITY_ORDER.indexOf(requested) > SEVERITY_ORDER.indexOf(cap) ? cap : requested;
}

export type FindingInput = Omit<Finding, 'severity'> & { requestedSeverity: FindingSeverity };

/**
 * The only supported way to construct a Finding. Enforces the confidence cap
 * at construction time so a violating Finding cannot be built by callers.
 */
export function createFinding(input: FindingInput): Finding {
  const { requestedSeverity, ...rest } = input;
  return { ...rest, severity: capSeverityByConfidence(requestedSeverity, input.confidence) };
}
