import { describe, expect, it } from 'vitest';
import { renderHtml } from '@reports/html-report.js';
import { createFinding } from '@core/types/finding.js';
import { buildTarget } from '@core/types/target.js';
import type { AuditResult } from '@core/types/index.js';

function baseResult(overrides: Partial<AuditResult> = {}): AuditResult {
  return {
    id: 'r1',
    target: buildTarget('https://example.com'),
    authorizationMode: 'prospect',
    profile: 'standard',
    status: 'completed',
    startedAt: '2026-01-01T00:00:00.000Z',
    finishedAt: '2026-01-01T00:00:05.000Z',
    isWordPress: true,
    scannerResults: [],
    findings: [],
    insights: [],
    limitations: [],
    ...overrides,
  };
}

describe('renderHtml', () => {
  it('renders a valid HTML document containing the target domain and status', async () => {
    const html = await renderHtml(baseResult(), 'en');

    expect(html).toContain('<!doctype html>');
    expect(html).toContain('example.com');
    expect(html).toContain('Completed');
    expect(html).not.toContain('{{'); // no leftover template tokens
  });

  it('renders in the requested locale independently of any global CLI locale state', async () => {
    const html = await renderHtml(baseResult(), 'pl');

    expect(html).toContain('Zakończony');
  });

  it('HTML-escapes dynamic values so a hostile header value cannot inject markup', async () => {
    const finding = createFinding({
      id: 'f1',
      category: 'security',
      confidence: 'confirmed',
      requestedSeverity: 'info',
      sourceLayer: 1,
      businessImpact: 'weak',
      recommendationKey: 'finding.header.infoDisclosure.recommendation',
      evidence: [
        {
          descriptionKey: 'finding.header.infoDisclosure.evidence',
          params: { header: 'server', value: '<script>alert(1)</script>' },
        },
      ],
    });

    const html = await renderHtml(baseResult({ findings: [finding] }), 'en');

    expect(html).not.toContain('<script>alert(1)</script>');
    expect(html).toContain('&lt;script&gt;');
  });

  it('shows an empty-state message when there are no findings', async () => {
    const html = await renderHtml(baseResult(), 'en');

    expect(html).toContain('No issues were identified.');
  });

  it('renders scores, insights, and limitations when present', async () => {
    const result = baseResult({
      scores: {
        categories: [
          { category: 'security', value: 88, deductions: [] },
          { category: 'maintenance', value: 100, deductions: [] },
          { category: 'performance', value: 100, deductions: [] },
          { category: 'seo', value: 100, deductions: [] },
          { category: 'infrastructure', value: 100, deductions: [] },
        ],
        overall: 88,
      },
      insights: [
        { findingIds: ['f1'], messageKey: 'insight.priority', messageParams: { count: 1 } },
      ],
      limitations: ['tls-scanner failed: handshake failed'],
    });

    const html = await renderHtml(result, 'en');

    expect(html).toContain('88');
    expect(html).toContain('This audit identified 1 issue(s)');
    expect(html).toContain('tls-scanner failed: handshake failed');
  });

  it('includes the consent artifact and audit-mode disclaimer when present', async () => {
    const result = baseResult({
      authorizationMode: 'audit',
      consentArtifact: {
        targetDomain: 'example.com',
        confirmed: true,
        timestamp: '2026-01-01T00:00:00.000Z',
        source: 'cli-flag',
      },
    });

    const html = await renderHtml(result, 'en');

    expect(html).toContain('Authorization record');
    expect(html).toContain('explicit authorization granted');
  });
});
