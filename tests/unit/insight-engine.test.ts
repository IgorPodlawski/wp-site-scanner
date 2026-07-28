import { describe, expect, it } from 'vitest';
import { generateInsights } from '@analysis/insight-engine.js';
import { createFinding } from '@core/types/finding.js';
import type { Finding } from '@core/types/index.js';

function finding(overrides: Partial<Parameters<typeof createFinding>[0]> = {}): Finding {
  return createFinding({
    id: overrides.id ?? 'f1',
    category: 'security',
    confidence: 'confirmed',
    severity: 'low',
    sourceLayer: 1,
    businessImpact: 'weak',
    recommendationKey: 'finding.header.missingCsp.recommendation',
    evidence: [],
    ...overrides,
  });
}

describe('generateInsights', () => {
  it('returns no insights when there are no findings', () => {
    expect(generateInsights([])).toEqual([]);
  });

  it('groups missing-header findings into one insight referencing all of them', () => {
    const f1 = finding({ id: 'f1', recommendationKey: 'finding.header.missingCsp.recommendation' });
    const f2 = finding({
      id: 'f2',
      recommendationKey: 'finding.header.missingXFrameOptions.recommendation',
    });

    const insights = generateInsights([f1, f2]);

    expect(insights).toHaveLength(1);
    expect(insights[0]).toEqual({
      findingIds: ['f1', 'f2'],
      messageKey: 'insight.missingSecurityHeaders',
      messageParams: { count: 2 },
    });
  });

  it('does not produce a missing-headers insight when there are no matching findings', () => {
    const f1 = finding({
      id: 'f1',
      recommendationKey: 'finding.tls.outdatedProtocol.recommendation',
    });

    const insights = generateInsights([f1]);

    expect(insights.some((i) => i.messageKey === 'insight.missingSecurityHeaders')).toBe(false);
  });

  it('groups outdated plugin/theme/core findings under one insight, based on finding.component.isOutdated', () => {
    const f1 = finding({
      id: 'f1',
      category: 'maintenance',
      recommendationKey: 'finding.component.plugin.outdated.recommendation',
      component: { kind: 'plugin', slug: 'akismet', isOutdated: true, vulnerabilities: [] },
    });
    const f2 = finding({
      id: 'f2',
      category: 'maintenance',
      recommendationKey: 'finding.component.theme.outdated.recommendation',
      component: {
        kind: 'theme',
        slug: 'twentytwentyfour',
        isOutdated: true,
        vulnerabilities: [],
      },
    });
    const f3 = finding({
      id: 'f3',
      category: 'maintenance',
      confidence: 'confirmed',
      severity: 'medium',
      recommendationKey: 'finding.component.core.outdated.recommendation',
      component: {
        kind: 'core',
        slug: 'wordpress-core',
        isOutdated: true,
        vulnerabilities: [],
      },
    });

    const insights = generateInsights([f1, f2, f3]);
    const outdated = insights.find((i) => i.messageKey === 'insight.outdatedComponents');

    expect(outdated).toEqual({
      findingIds: ['f1', 'f2', 'f3'],
      messageKey: 'insight.outdatedComponents',
      messageParams: { count: 3 },
    });
  });

  it('groups vulnerable components under insight.knownVulnerabilities, including core (a previous gap)', () => {
    const f1 = finding({
      id: 'f1',
      category: 'security',
      confidence: 'confirmed',
      severity: 'critical',
      recommendationKey: 'finding.component.plugin.vulnerable.recommendation',
      component: {
        kind: 'plugin',
        slug: 'akismet',
        isOutdated: false,
        vulnerabilities: [{ severity: 'critical', confirmed: true }],
      },
    });
    const f2 = finding({
      id: 'f2',
      category: 'security',
      confidence: 'confirmed',
      severity: 'high',
      recommendationKey: 'finding.component.core.vulnerable.recommendation',
      component: {
        kind: 'core',
        slug: 'wordpress-core',
        isOutdated: false,
        vulnerabilities: [{ severity: 'high', confirmed: true }],
      },
    });

    const insights = generateInsights([f1, f2]);
    const known = insights.find((i) => i.messageKey === 'insight.knownVulnerabilities');

    expect(known).toEqual({
      findingIds: ['f1', 'f2'],
      messageKey: 'insight.knownVulnerabilities',
      messageParams: { count: 2 },
    });
  });

  it('raises a priority insight for high/critical findings regardless of their other grouping', () => {
    const f1 = finding({
      id: 'f1',
      category: 'security',
      confidence: 'confirmed',
      severity: 'critical',
      recommendationKey: 'finding.endpoint.configBackupExposed.recommendation',
    });

    const insights = generateInsights([f1]);

    const priority = insights.find((i) => i.messageKey === 'insight.priority');
    const endpoints = insights.find((i) => i.messageKey === 'insight.exposedEndpoints');
    expect(priority).toEqual({
      findingIds: ['f1'],
      messageKey: 'insight.priority',
      messageParams: { count: 1 },
    });
    // the same finding can legitimately surface under more than one narrative angle
    expect(endpoints).toEqual({
      findingIds: ['f1'],
      messageKey: 'insight.exposedEndpoints',
      messageParams: { count: 1 },
    });
  });

  it('never invents a finding reference — every id traces back to an actual finding', () => {
    const f1 = finding({ id: 'f1' });
    const insights = generateInsights([f1]);

    for (const insight of insights) {
      for (const id of insight.findingIds) {
        expect(id).toBe('f1');
      }
    }
  });
});
