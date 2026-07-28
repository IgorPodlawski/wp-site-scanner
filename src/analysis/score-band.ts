/**
 * 0-100 "worse to better" banding for numbers backed by a real external
 * measurement (currently just PageSpeed's Lighthouse performance score —
 * see scoring-engine.ts's `calculateMeasuredScores`). Same thresholds
 * Google itself uses for its own bucketing.
 */
export type ScoreBand = 'good' | 'fair' | 'poor';

export const SCORE_BAND_THRESHOLDS = { poor: 50, good: 90 } as const;

export function getScoreBand(value: number): ScoreBand {
  if (value < SCORE_BAND_THRESHOLDS.poor) return 'poor';
  if (value < SCORE_BAND_THRESHOLDS.good) return 'fair';
  return 'good';
}
