/**
 * Numeric 0-100 scores now exist ONLY where the number comes from a real,
 * deterministic external measurement (Google Lighthouse via PageSpeed) — see
 * analysis/scoring-engine.ts's `calculateMeasuredScores`. Security,
 * Maintenance, Infrastructure and Overall are qualitative instead (see
 * rating.ts). SEO isn't listed here: there is no real Lighthouse SEO
 * category wired up yet, so there is no number to show for it.
 */
export type MeasuredCategory = 'performance';

export interface MeasuredCategoryScore {
  category: MeasuredCategory;
  /** The real Lighthouse/PageSpeed score, 0-100 — never a synthetic deduction. */
  value: number;
}

export interface MeasuredScoreSummary {
  categories: MeasuredCategoryScore[];
}
