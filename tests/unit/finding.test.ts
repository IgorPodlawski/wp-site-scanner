import { describe, expect, it } from 'vitest';
import { createFinding } from '@core/types/finding.js';

describe('createFinding', () => {
  const baseInput = {
    id: 'f1',
    category: 'security' as const,
    confidence: 'inferred' as const,
    sourceLayer: 1 as const,
    businessImpact: 'strong' as const,
    recommendationKey: 'rec.key',
    evidence: [],
  };

  it('takes severity as given, regardless of confidence', () => {
    const finding = createFinding({ ...baseInput, confidence: 'inferred', severity: 'critical' });

    expect(finding.severity).toBe('critical');
    expect(finding.confidence).toBe('inferred');
  });

  it('carries the optional component field through unchanged', () => {
    const finding = createFinding({
      ...baseInput,
      severity: 'high',
      component: {
        kind: 'plugin',
        slug: 'akismet',
        isOutdated: false,
        vulnerabilities: [{ severity: 'high', confirmed: true, knownExploited: false }],
      },
    });

    expect(finding.component).toEqual({
      kind: 'plugin',
      slug: 'akismet',
      isOutdated: false,
      vulnerabilities: [{ severity: 'high', confirmed: true, knownExploited: false }],
    });
  });
});
