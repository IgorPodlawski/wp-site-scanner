import { describe, expect, it } from 'vitest';
import { calculateScores, BASE_PENALTY, CONFIDENCE_WEIGHT } from '@analysis/scoring-engine.js';
import { createFinding } from '@core/types/finding.js';
import type {
  ComponentFindingInfo,
  Finding,
  FindingCategory,
  FindingConfidence,
  FindingSeverity,
} from '@core/types/index.js';

function finding(
  category: FindingCategory,
  severity: FindingSeverity,
  confidence: FindingConfidence,
  component?: ComponentFindingInfo,
): Finding {
  return createFinding({
    id: `${category}-${severity}-${confidence}-${Math.random()}`,
    category,
    confidence,
    severity,
    sourceLayer: 1,
    businessImpact: 'weak',
    recommendationKey: 'rec.key',
    evidence: [],
    ...(component ? { component } : {}),
  });
}

function componentFinding(
  severity: FindingSeverity,
  confidence: FindingConfidence,
  vulnerabilitySeverities: FindingSeverity[],
): Finding {
  return finding('security', severity, confidence, {
    kind: 'plugin',
    slug: 'akismet',
    isOutdated: false,
    vulnerabilitySeverities,
  });
}

describe('calculateScores — plain findings', () => {
  it('starts every category and overall at 100 when there are no findings', () => {
    const result = calculateScores([]);

    expect(result.overall).toBe(100);
    expect(result.categories).toHaveLength(5);
    expect(result.categories.every((c) => c.value === 100 && c.deductions.length === 0)).toBe(true);
  });

  it('deducts round(basePenalty * confidenceWeight) for a plain finding, only from its own category', () => {
    const f = finding('security', 'medium', 'confirmed');
    const result = calculateScores([f]);

    const amount = Math.round(BASE_PENALTY.medium * CONFIDENCE_WEIGHT.confirmed);
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

  it('deducts less for lower confidence at the same severity', () => {
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

    const expectedAmount =
      Math.round(BASE_PENALTY.low * CONFIDENCE_WEIGHT.confirmed) +
      Math.round(BASE_PENALTY.medium * CONFIDENCE_WEIGHT.confirmed);
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

describe('calculateScores — component vulnerability aggregation', () => {
  it('deducts the plain formula for a single-vulnerability component (no aggregation needed)', () => {
    const f = componentFinding('high', 'confirmed', ['high']);
    const result = calculateScores([f]);

    expect(result.overall).toBe(100 - Math.round(BASE_PENALTY.high * CONFIDENCE_WEIGHT.confirmed));
  });

  it('gives full weight to the worst vulnerability and 25% weight to the rest', () => {
    // Kept well under the 30 cap so this isolates the aggregation formula
    // itself, not the cap (that's a separate test below).
    const f = componentFinding('high', 'confirmed', ['high', 'medium', 'low']);
    const result = calculateScores([f]);

    const expected = Math.round(
      (BASE_PENALTY.high + BASE_PENALTY.medium * 0.25 + BASE_PENALTY.low * 0.25) *
        CONFIDENCE_WEIGHT.confirmed,
    );
    const security = result.categories.find((c) => c.category === 'security')!;
    expect(security.deductions[0]!.amount).toBe(expected);
    expect(security.deductions[0]!.amount).toBeLessThan(30);
  });

  it('scales the aggregated deduction by confidence, same as a plain finding', () => {
    const confirmed = calculateScores([
      componentFinding('high', 'confirmed', ['high', 'high']),
    ]).overall;
    const inferred = calculateScores([
      componentFinding('high', 'inferred', ['high', 'high']),
    ]).overall;

    expect(inferred).toBeGreaterThan(confirmed);
  });

  it('caps a single component finding contribution at 30, even with many critical vulnerabilities', () => {
    const manyVulns = Array.from({ length: 10 }, () => 'critical' as const);
    const f = componentFinding('critical', 'confirmed', manyVulns);
    const result = calculateScores([f]);

    const security = result.categories.find((c) => c.category === 'security')!;
    expect(security.deductions[0]!.amount).toBe(30);
    expect(result.overall).toBe(70);
  });

  it('never lets a single component reduce overall below 70, regardless of vulnerability count', () => {
    const manyVulns = Array.from({ length: 50 }, () => 'critical' as const);
    const f = componentFinding('critical', 'confirmed', manyVulns);

    const result = calculateScores([f]);

    expect(result.overall).toBeGreaterThanOrEqual(70);
  });

  it('does not let one capped component finding suppress deductions from unrelated findings', () => {
    const manyVulns = Array.from({ length: 10 }, () => 'critical' as const);
    const component = componentFinding('critical', 'confirmed', manyVulns);
    const other = finding('security', 'medium', 'confirmed');

    const result = calculateScores([component, other]);

    const expectedOther = Math.round(BASE_PENALTY.medium * CONFIDENCE_WEIGHT.confirmed);
    expect(result.overall).toBe(100 - 30 - expectedOther);
  });
});
