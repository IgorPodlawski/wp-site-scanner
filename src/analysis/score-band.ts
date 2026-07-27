/**
 * Shared 0-100 "worse to better" scale used both by our own category scores
 * (scoring-engine.ts, starts at 100 and is deducted) and by PageSpeed's
 * Lighthouse performance score — same thresholds Google itself uses for its
 * own bucketing, reused here so the report speaks about both kinds of score
 * with one consistent vocabulary instead of two unrelated cutoffs.
 */
export type ScoreBand = 'good' | 'fair' | 'poor';

export const SCORE_BAND_THRESHOLDS = { poor: 50, good: 90 } as const;

export function getScoreBand(value: number): ScoreBand {
  if (value < SCORE_BAND_THRESHOLDS.poor) return 'poor';
  if (value < SCORE_BAND_THRESHOLDS.good) return 'fair';
  return 'good';
}
