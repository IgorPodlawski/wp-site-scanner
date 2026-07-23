import type {
  CategoryScore,
  Finding,
  FindingCategory,
  FindingConfidence,
  FindingSeverity,
  ScoreSummary,
} from '../core/types/index.js';

/**
 * The single, reviewable place deduction amounts live (per CLAUDE.md:
 * "keep the deduction table explicit and in one place"). Monotonic in both
 * dimensions — worse severity and higher confidence both deduct more — but
 * otherwise arbitrary hand-picked integers. No invented mathematical
 * complexity: scoring only prioritizes, it does not need a formula.
 */
export const DEDUCTION_TABLE: Record<FindingSeverity, Record<FindingConfidence, number>> = {
  info: { inferred: 1, corroborated: 1, confirmed: 2 },
  low: { inferred: 3, corroborated: 4, confirmed: 5 },
  medium: { inferred: 6, corroborated: 8, confirmed: 10 },
  high: { inferred: 10, corroborated: 14, confirmed: 18 },
  critical: { inferred: 15, corroborated: 22, confirmed: 30 },
};

const SCORED_CATEGORIES: readonly FindingCategory[] = [
  'security',
  'maintenance',
  'performance',
  'seo',
  'infrastructure',
];

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
    const amount = DEDUCTION_TABLE[finding.severity][finding.confidence];

    const categoryScore = categories[finding.category];
    categoryScore.deductions.push({ findingId: finding.id, amount });
    categoryScore.value = Math.max(0, categoryScore.value - amount);

    overall = Math.max(0, overall - amount);
  }

  return { categories: SCORED_CATEGORIES.map((category) => categories[category]), overall };
}
