import { describe, expect, it } from 'vitest';
import { calculateScores, DEDUCTION_TABLE } from '@analysis/scoring-engine.js';
import { createFinding } from '@core/types/finding.js';
import type {
  Finding,
  FindingCategory,
  FindingConfidence,
  FindingSeverity,
} from '@core/types/index.js';

function finding(
  category: FindingCategory,
  requestedSeverity: FindingSeverity,
  confidence: FindingConfidence,
): Finding {
  return createFinding({
    id: `${category}-${requestedSeverity}-${confidence}`,
    category,
    confidence,
    requestedSeverity,
    sourceLayer: 1,
    businessImpact: 'weak',
    recommendationKey: 'rec.key',
    evidence: [],
  });
}

describe('calculateScores', () => {
  it('starts every category and overall at 100 when there are no findings', () => {
    const result = calculateScores([]);

    expect(result.overall).toBe(100);
    expect(result.categories).toHaveLength(5);
    expect(result.categories.every((c) => c.value === 100 && c.deductions.length === 0)).toBe(true);
  });

  it('deducts a finding only from its own category, plus overall', () => {
    const f = finding('security', 'medium', 'confirmed');
    const result = calculateScores([f]);

    const amount = DEDUCTION_TABLE.medium.confirmed;
    const security = result.categories.find((c) => c.category === 'security')!;
    const maintenance = result.categories.find((c) => c.category === 'maintenance')!;

    expect(security.value).toBe(100 - amount);
    expect(security.deductions).toEqual([{ findingId: f.id, amount }]);
    expect(maintenance.value).toBe(100);
    expect(result.overall).toBe(100 - amount);
  });

  it('deducts more for higher severity at the same confidence', () => {
    const low = calculateScores([finding('security', 'low', 'confirmed')]).overall;
    const critical = calculateScores([finding('security', 'critical', 'confirmed')]).overall;

    expect(critical).toBeLessThan(low);
  });

  it('deducts less for lower confidence at the same requested severity', () => {
    const inferred = calculateScores([finding('security', 'medium', 'inferred')]).overall;
    const confirmed = calculateScores([finding('security', 'medium', 'confirmed')]).overall;

    expect(inferred).toBeGreaterThan(confirmed);
  });

  it('accumulates deductions from multiple findings in the same category', () => {
    const findings = [
      finding('performance', 'low', 'confirmed'),
      finding('performance', 'medium', 'confirmed'),
    ];
    const result = calculateScores(findings);

    const expectedAmount = DEDUCTION_TABLE.low.confirmed + DEDUCTION_TABLE.medium.confirmed;
    const performance = result.categories.find((c) => c.category === 'performance')!;

    expect(performance.value).toBe(100 - expectedAmount);
    expect(performance.deductions).toHaveLength(2);
    expect(result.overall).toBe(100 - expectedAmount);
  });

  it('clamps a category (and overall) at 0 rather than going negative', () => {
    const findings = Array.from({ length: 20 }, (_, i) => ({
      ...finding('security', 'critical', 'confirmed'),
      id: `f${i}`,
    }));
    const result = calculateScores(findings);

    const security = result.categories.find((c) => c.category === 'security')!;
    expect(security.value).toBe(0);
    expect(result.overall).toBe(0);
    // every finding is still recorded, even past the floor
    expect(security.deductions).toHaveLength(20);
  });
});
