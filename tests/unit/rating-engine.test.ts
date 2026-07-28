import { describe, expect, it } from 'vitest';
import {
  rateSecurity,
  rateMaintenance,
  rateInfrastructure,
  rateOverall,
  calculateRatings,
  MAINTENANCE_URGENT_OUTDATED,
} from '@analysis/rating-engine.js';
import {
  calculateReportCounters,
  SECURITY_COVERAGE_ENRICHMENT,
  MAINTENANCE_COVERAGE_ENRICHMENT,
} from '@analysis/finding-engine.js';
import { createFinding } from '@core/types/finding.js';
import type { CategoryRating, Finding, FindingSeverity } from '@core/types/index.js';
import { buildTestContext, buildHttpResponse } from '../support/test-context.js';

let nextId = 0;
function componentFinding(
  vulnerabilities: Array<{ severity: FindingSeverity; confirmed: boolean }>,
  overrides: Partial<Finding> = {},
): Finding {
  nextId += 1;
  return createFinding({
    id: `component-${nextId}`,
    category: vulnerabilities.length > 0 ? 'security' : 'maintenance',
    confidence: 'confirmed',
    severity: 'medium',
    sourceLayer: 'third-party',
    businessImpact: 'medium',
    recommendationKey: 'finding.component.plugin.vulnerable.recommendation',
    evidence: [],
    component: { kind: 'plugin', slug: 'akismet', isOutdated: false, vulnerabilities },
    ...overrides,
  });
}

function endpointFinding(recommendationKey: string, severity: FindingSeverity): Finding {
  nextId += 1;
  return createFinding({
    id: `endpoint-${nextId}`,
    category: 'security',
    confidence: 'confirmed',
    severity,
    sourceLayer: 2,
    businessImpact: 'medium',
    recommendationKey,
    evidence: [],
  });
}

function infraFinding(recommendationKey: string, severity: FindingSeverity): Finding {
  nextId += 1;
  return createFinding({
    id: `infra-${nextId}`,
    category: 'infrastructure',
    confidence: 'confirmed',
    severity,
    sourceLayer: 1,
    businessImpact: 'medium',
    recommendationKey,
    evidence: [],
  });
}

describe('rateSecurity', () => {
  it('is urgent when a vulnerability is confirmed and high/critical severity', () => {
    const finding = componentFinding([{ severity: 'critical', confirmed: true }]);
    const context = buildTestContext();
    context.setEnrichment(SECURITY_COVERAGE_ENRICHMENT, 'assessed');

    expect(rateSecurity(context, [finding]).level).toBe('urgent');
  });

  it('is urgent when an endpoint finding is high/critical severity, even with zero vulnerabilities', () => {
    const finding = endpointFinding(
      'finding.endpoint.configBackupExposed.recommendation',
      'critical',
    );
    const context = buildTestContext();
    context.setEnrichment(SECURITY_COVERAGE_ENRICHMENT, 'assessed');

    expect(rateSecurity(context, [finding]).level).toBe('urgent');
  });

  it('is attention (not urgent) for a high/critical vulnerability that is only potential (not confirmed)', () => {
    const finding = componentFinding([{ severity: 'critical', confirmed: false }]);
    const context = buildTestContext();
    context.setEnrichment(SECURITY_COVERAGE_ENRICHMENT, 'assessed');

    expect(rateSecurity(context, [finding]).level).toBe('attention');
  });

  it('is attention for a confirmed medium/low vulnerability', () => {
    const finding = componentFinding([{ severity: 'medium', confirmed: true }]);
    const context = buildTestContext();
    context.setEnrichment(SECURITY_COVERAGE_ENRICHMENT, 'assessed');

    expect(rateSecurity(context, [finding]).level).toBe('attention');
  });

  it('is attention for a low-severity endpoint finding (e.g. xmlrpc enabled)', () => {
    const finding = endpointFinding('finding.endpoint.xmlrpcEnabled.recommendation', 'low');
    const context = buildTestContext();
    context.setEnrichment(SECURITY_COVERAGE_ENRICHMENT, 'assessed');

    expect(rateSecurity(context, [finding]).level).toBe('attention');
  });

  it('is clear when nothing was found and WPScan coverage was assessed', () => {
    const context = buildTestContext();
    context.setEnrichment(SECURITY_COVERAGE_ENRICHMENT, 'assessed');

    expect(rateSecurity(context, []).level).toBe('clear');
  });

  it('is not_assessed when nothing was found and WPScan coverage is missing (prospect mode / no token)', () => {
    const context = buildTestContext();
    context.setEnrichment(SECURITY_COVERAGE_ENRICHMENT, 'not_assessed');

    expect(rateSecurity(context, []).level).toBe('not_assessed');
  });

  it('defaults to not_assessed when the coverage flag was never written at all', () => {
    const context = buildTestContext();

    expect(rateSecurity(context, []).level).toBe('not_assessed');
  });

  it('never looks at header-hygiene findings — a header-only finding does not move Security off clear', () => {
    const headerFinding = createFinding({
      id: 'header-1',
      category: 'security',
      confidence: 'confirmed',
      severity: 'low',
      sourceLayer: 1,
      businessImpact: 'weak',
      recommendationKey: 'finding.header.missingHsts.recommendation',
      evidence: [],
    });
    const context = buildTestContext();
    context.setEnrichment(SECURITY_COVERAGE_ENRICHMENT, 'assessed');

    expect(rateSecurity(context, [headerFinding]).level).toBe('clear');
  });

  it('escalated component badges do not drive the threshold — reads raw confirmed+severity, not Finding.severity', () => {
    // A component finding whose *badge* got escalated to 'high' (several
    // mediums) must not make Security urgent on its own — only a raw
    // confirmed high/critical vulnerability entry does.
    const finding = componentFinding(
      [
        { severity: 'medium', confirmed: true },
        { severity: 'medium', confirmed: true },
        { severity: 'medium', confirmed: true },
      ],
      { severity: 'high' },
    );
    const context = buildTestContext();
    context.setEnrichment(SECURITY_COVERAGE_ENRICHMENT, 'assessed');

    expect(rateSecurity(context, [finding]).level).toBe('attention');
  });
});

describe('rateMaintenance', () => {
  function counters(outdatedComponentCount: number) {
    return {
      componentsWithVulnerabilities: 0,
      uniqueVulnerabilityCount: 0,
      outdatedComponentCount,
      findingsBySeverity: { info: 0, low: 0, medium: 0, high: 0, critical: 0 },
    };
  }

  it('is urgent when WordPress core itself is outdated', () => {
    const coreFinding = createFinding({
      id: 'core-1',
      category: 'maintenance',
      confidence: 'confirmed',
      severity: 'medium',
      sourceLayer: 'third-party',
      businessImpact: 'medium',
      recommendationKey: 'finding.component.core.outdated.recommendation',
      evidence: [],
      component: { kind: 'core', slug: 'wordpress-core', isOutdated: true, vulnerabilities: [] },
    });
    const context = buildTestContext();
    context.setEnrichment(MAINTENANCE_COVERAGE_ENRICHMENT, 'assessed');

    expect(rateMaintenance(context, [coreFinding], counters(1)).level).toBe('urgent');
  });

  it(`is urgent at exactly the MAINTENANCE_URGENT_OUTDATED boundary (${MAINTENANCE_URGENT_OUTDATED})`, () => {
    const context = buildTestContext();
    context.setEnrichment(MAINTENANCE_COVERAGE_ENRICHMENT, 'assessed');

    expect(rateMaintenance(context, [], counters(MAINTENANCE_URGENT_OUTDATED)).level).toBe(
      'urgent',
    );
    expect(rateMaintenance(context, [], counters(MAINTENANCE_URGENT_OUTDATED - 1)).level).toBe(
      'attention',
    );
  });

  it('is attention when at least one non-core component is outdated', () => {
    const context = buildTestContext();
    context.setEnrichment(MAINTENANCE_COVERAGE_ENRICHMENT, 'assessed');

    expect(rateMaintenance(context, [], counters(1)).level).toBe('attention');
  });

  it('is clear when nothing is outdated and .org coverage was assessed', () => {
    const context = buildTestContext();
    context.setEnrichment(MAINTENANCE_COVERAGE_ENRICHMENT, 'assessed');

    expect(rateMaintenance(context, [], counters(0)).level).toBe('clear');
  });

  it('is not_assessed when nothing is outdated but .org coverage failed entirely', () => {
    const context = buildTestContext();
    context.setEnrichment(MAINTENANCE_COVERAGE_ENRICHMENT, 'not_assessed');

    expect(rateMaintenance(context, [], counters(0)).level).toBe('not_assessed');
  });
});

describe('rateInfrastructure', () => {
  it('is attention when any infrastructure-category finding is present (never urgent)', () => {
    const finding = infraFinding('finding.tls.invalidCertificate.recommendation', 'high');
    const context = buildTestContext();

    expect(rateInfrastructure(context, [finding]).level).toBe('attention');
  });

  it('is attention for a genuinely HTTP-only site (the "no HTTPS" finding)', () => {
    const finding = infraFinding('finding.infrastructure.noHttps.recommendation', 'high');
    const context = buildTestContext();
    context.setHttpResponse(buildHttpResponse('', { url: 'http://example.com/' }));

    expect(rateInfrastructure(context, [finding]).level).toBe('attention');
  });

  it('is clear when the effective (post-redirect) URL is https and tls-scanner ran successfully', () => {
    const context = buildTestContext({ target: 'http://example.com' });
    context.setHttpResponse(buildHttpResponse('', { url: 'https://example.com/' }));
    context.addScannerResult({
      scannerName: 'tls-scanner',
      status: 'ok',
      data: { protocol: 'TLSv1.3', authorized: true },
      durationMs: 0,
    });

    expect(rateInfrastructure(context, []).level).toBe('clear');
  });

  it('is not_assessed when the effective URL is https but tls-scanner produced no successful result', () => {
    const context = buildTestContext();
    context.setHttpResponse(buildHttpResponse('', { url: 'https://example.com/' }));

    expect(rateInfrastructure(context, []).level).toBe('not_assessed');
  });
});

describe('rateOverall', () => {
  function rating(level: CategoryRating['level']): CategoryRating {
    return { category: 'security', level, reasons: [] };
  }

  it('is the worst of the assessed categories', () => {
    expect(rateOverall([rating('clear'), rating('attention'), rating('urgent')]).level).toBe(
      'urgent',
    );
    expect(rateOverall([rating('clear'), rating('attention')]).level).toBe('attention');
    expect(rateOverall([rating('clear'), rating('clear')]).level).toBe('clear');
  });

  it('ignores not_assessed categories when at least one other category was assessed', () => {
    expect(rateOverall([rating('not_assessed'), rating('attention')]).level).toBe('attention');
    expect(rateOverall([rating('not_assessed'), rating('clear')]).level).toBe('clear');
  });

  it('is not_assessed only when every category is not_assessed', () => {
    expect(rateOverall([rating('not_assessed'), rating('not_assessed')]).level).toBe(
      'not_assessed',
    );
  });
});

describe('calculateRatings', () => {
  it('assembles all three categories plus overall', () => {
    const context = buildTestContext();
    context.setEnrichment(SECURITY_COVERAGE_ENRICHMENT, 'assessed');
    context.setEnrichment(MAINTENANCE_COVERAGE_ENRICHMENT, 'assessed');
    context.addScannerResult({
      scannerName: 'tls-scanner',
      status: 'ok',
      data: { protocol: 'TLSv1.3', authorized: true },
      durationMs: 0,
    });

    const findings: Finding[] = [];
    const result = calculateRatings(context, findings, calculateReportCounters(findings));

    expect(result.categories.map((c) => c.category)).toEqual([
      'security',
      'maintenance',
      'infrastructure',
    ]);
    expect(result.categories.every((c) => c.level === 'clear')).toBe(true);
    expect(result.overall.level).toBe('clear');
  });
});
