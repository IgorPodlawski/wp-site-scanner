import { describe, expect, it } from 'vitest';
import { capSeverityByConfidence, createFinding } from '@core/types/finding.js';

describe('capSeverityByConfidence', () => {
  it('caps inferred confidence at medium', () => {
    expect(capSeverityByConfidence('critical', 'inferred')).toBe('medium');
    expect(capSeverityByConfidence('low', 'inferred')).toBe('low');
  });

  it('caps corroborated confidence at high', () => {
    expect(capSeverityByConfidence('critical', 'corroborated')).toBe('high');
    expect(capSeverityByConfidence('medium', 'corroborated')).toBe('medium');
  });

  it('allows confirmed confidence to reach critical', () => {
    expect(capSeverityByConfidence('critical', 'confirmed')).toBe('critical');
  });
});

describe('createFinding', () => {
  const baseInput = {
    id: 'f1',
    category: 'security' as const,
    sourceLayer: 1 as const,
    businessImpact: 'strong' as const,
    recommendationKey: 'rec.key',
    evidence: [],
  };

  it('does not allow an inferred finding to be built as critical', () => {
    const finding = createFinding({
      ...baseInput,
      confidence: 'inferred',
      requestedSeverity: 'critical',
    });
    expect(finding.severity).toBe('medium');
  });

  it('allows a confirmed finding to be built as critical', () => {
    const finding = createFinding({
      ...baseInput,
      confidence: 'confirmed',
      requestedSeverity: 'critical',
    });
    expect(finding.severity).toBe('critical');
  });
});
