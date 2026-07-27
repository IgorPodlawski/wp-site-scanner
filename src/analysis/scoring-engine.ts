import type {
  CategoryScore,
  Finding,
  FindingCategory,
  FindingConfidence,
  FindingSeverity,
  ScoreSummary,
} from '../core/types/index.js';

/**
 * The single, reviewable place deduction inputs live (per CLAUDE.md: "keep
 * the deduction table explicit and in one place"). `BASE_PENALTY` is driven
 * purely by severity (which itself now comes from CVSS/WPScan data, never
 * from confidence — see finding-engine.ts). `CONFIDENCE_WEIGHT` is the ONLY
 * place confidence affects a score: it scales the deduction, it never
 * changes which bucket (severity) a finding falls into.
 */
export const BASE_PENALTY: Record<FindingSeverity, number> = {
  info: 0,
  low: 3,
  medium: 8,
  high: 18,
  critical: 30,
};

export const CONFIDENCE_WEIGHT: Record<FindingConfidence, number> = {
  confirmed: 1.0,
  corroborated: 0.8,
  inferred: 0.5,
};

/**
 * Hard cap on any single component (WordPress core/plugin/theme) finding's
 * contribution to a single score — its category and `overall` alike. Since
 * every contribution to `overall` is capped the same way, no single
 * component can ever reduce `overall` (or any category) by more than this,
 * regardless of how many vulnerabilities it has.
 */
const COMPONENT_DEDUCTION_CAP = 30;

/** Vulnerabilities beyond the worst one are weighted down rather than each counted in full — the component already has a known problem; each additional one adds less marginal risk. */
const SECONDARY_VULNERABILITY_WEIGHT = 0.25;

const SCORED_CATEGORIES: readonly FindingCategory[] = [
  'security',
  'maintenance',
  'performance',
  'seo',
  'infrastructure',
];

/** Plain findings (no per-vulnerability breakdown): base penalty for the finding's own severity, scaled by confidence. */
function plainDeduction(finding: Finding): number {
  return Math.round(BASE_PENALTY[finding.severity] * CONFIDENCE_WEIGHT[finding.confidence]);
}

/**
 * A component finding with N applicable vulnerabilities: full base penalty
 * for the worst one, 25% weight for each of the rest, then the confidence
 * weight is applied to the whole sum (confidence is a property of the
 * detected component version, shared across all its vulnerabilities) —
 * finally capped at COMPONENT_DEDUCTION_CAP.
 */
function componentVulnerabilityDeduction(finding: Finding): number {
  const severities = finding.component!.vulnerabilitySeverities;
  const sortedBasePenalties = severities
    .map((severity) => BASE_PENALTY[severity])
    .sort((a, b) => b - a);
  const [worst, ...rest] = sortedBasePenalties;
  const raw =
    worst! + rest.reduce((sum, penalty) => sum + penalty * SECONDARY_VULNERABILITY_WEIGHT, 0);
  return Math.min(COMPONENT_DEDUCTION_CAP, Math.round(raw * CONFIDENCE_WEIGHT[finding.confidence]));
}

function deductionFor(finding: Finding): number {
  if (finding.component && finding.component.vulnerabilitySeverities.length > 0) {
    return componentVulnerabilityDeduction(finding);
  }
  return plainDeduction(finding);
}

/**
 * Each category and 'overall' start at 100. A finding's deduction reduces
 * its own category; 'overall' is reduced by every finding regardless of
 * category, so it reflects the totality of what was found while the
 * per-category breakdown shows where it concentrates. A category's
 * displayed value is clamped at 0, but every deduction is still recorded
 * for review even past that floor.
 */
export function calculateScores(findings: readonly Finding[]): ScoreSummary {
  const categories = {} as Record<FindingCategory, CategoryScore>;
  for (const category of SCORED_CATEGORIES) {
    categories[category] = { category, value: 100, deductions: [] };
  }

  let overall = 100;

  for (const finding of findings) {
    const amount = deductionFor(finding);

    const categoryScore = categories[finding.category];
    categoryScore.deductions.push({ findingId: finding.id, amount });
    categoryScore.value = Math.max(0, categoryScore.value - amount);

    overall = Math.max(0, overall - amount);
  }

  return { categories: SCORED_CATEGORIES.map((category) => categories[category]), overall };
}
