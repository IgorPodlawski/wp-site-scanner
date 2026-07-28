import { describe, expect, it } from 'vitest';
import { calculateMeasuredScores } from '@analysis/scoring-engine.js';
import type { PageSpeedResult } from '@integrations/enrichment-types.js';

function pageSpeedResult(performanceScore: number): PageSpeedResult {
  return { performanceScore, coreWebVitals: {} };
}

describe('calculateMeasuredScores', () => {
  it('returns no categories when PageSpeed enrichment is unavailable', () => {
    expect(calculateMeasuredScores(undefined)).toEqual({ categories: [] });
  });

  it('returns the real PageSpeed score directly, not a synthetic deduction', () => {
    const result = calculateMeasuredScores(pageSpeedResult(42));

    expect(result.categories).toEqual([{ category: 'performance', value: 42 }]);
  });

  it('reports a good score (>=90) exactly as measured, not clamped or hidden', () => {
    const result = calculateMeasuredScores(pageSpeedResult(97));

    expect(result.categories).toEqual([{ category: 'performance', value: 97 }]);
  });
});
