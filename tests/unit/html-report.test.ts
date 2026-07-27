import { describe, expect, it } from 'vitest';
import { renderHtml } from '@reports/html-report.js';
import { createFinding } from '@core/types/finding.js';
import { buildTarget } from '@core/types/target.js';
import type { AuditResult, ComponentFindingInfo, Finding } from '@core/types/index.js';

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
      severity: 'info',
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

    expect(html).toContain('88/100');
    expect(html).toContain('This audit identified 1 issue(s)');
    expect(html).toContain('tls-scanner failed: handshake failed');
  });

  describe('score readability', () => {
    it('shows a 0-100 scale note and a good/fair/poor badge next to every score', async () => {
      const result = baseResult({
        scores: {
          categories: [
            { category: 'security', value: 30, deductions: [] },
            { category: 'maintenance', value: 70, deductions: [] },
            { category: 'performance', value: 95, deductions: [] },
            { category: 'seo', value: 100, deductions: [] },
            { category: 'infrastructure', value: 100, deductions: [] },
          ],
          overall: 30,
        },
      });

      const html = await renderHtml(result, 'en');

      expect(html).toContain('Each score is on a 0-100 scale');
      expect(html).toContain('30/100');
      expect(html).toContain('class="badge score-poor"');
      expect(html).toContain('70/100');
      expect(html).toContain('class="badge score-fair"');
      expect(html).toContain('95/100');
      expect(html).toContain('class="badge score-good"');
    });
  });

  it('does not render the consent artifact in the report, even when present on AuditResult', async () => {
    // Deliberate: the consent artifact is still captured and persisted on
    // AuditResult/JSON for audit mode's internal auditable-trail requirement
    // (see CLAUDE.md's "Consent artifact" section) — just not surfaced in
    // the human-readable report itself (client-facing decision).
    const result = baseResult({
      authorizationMode: 'audit',
      consentArtifact: {
        targetDomain: 'example.com',
        confirmed: true,
        timestamp: '2025-06-15T12:34:56.000Z',
        operatorNote: 'Approved by the client via email',
        source: 'cli-flag',
      },
    });

    const html = await renderHtml(result, 'en');

    expect(html).not.toContain('Authorization record');
    expect(html).not.toContain('explicit authorization granted');
    expect(html).not.toContain('2025-06-15T12:34:56.000Z');
    expect(html).not.toContain('Approved by the client via email');
    // The plain disclaimer is still shown, regardless of authorization mode.
    expect(html).toContain('This audit is based only on publicly available information.');
  });

  describe('core version visibility', () => {
    it('always shows the detected core version, even when no finding references it', async () => {
      const result = baseResult({
        scannerResults: [
          {
            scannerName: 'core-version-scanner',
            status: 'ok',
            data: {
              version: {
                value: '7.0.2',
                sources: ['asset-query-string'],
                confidence: 'inferred',
              },
            },
            durationMs: 0,
          },
        ],
        findings: [], // a healthy, up-to-date version produces no finding at all
      });

      const html = await renderHtml(result, 'en');

      expect(html).toContain('WordPress core version');
      expect(html).toContain('7.0.2');
      expect(html).toContain('Inferred');
    });

    it('shows "not detected" when the scanner found no version, instead of omitting the row', async () => {
      const result = baseResult({
        scannerResults: [
          {
            scannerName: 'core-version-scanner',
            status: 'ok',
            data: { version: undefined },
            durationMs: 0,
          },
        ],
      });

      const html = await renderHtml(result, 'en');

      expect(html).toContain('WordPress core version');
      expect(html).toContain('Not detected');
    });

    it('omits the core version row entirely for a non-WordPress target', async () => {
      const result = baseResult({ isWordPress: false, scannerResults: [] });

      const html = await renderHtml(result, 'en');

      expect(html).not.toContain('report.summary.coreVersion');
      expect(html).not.toContain('WordPress core version');
    });
  });

  describe('report counters', () => {
    it('renders the three counter rows when counters are present', async () => {
      const result = baseResult({
        counters: {
          componentsWithVulnerabilities: 2,
          uniqueVulnerabilityCount: 5,
          outdatedComponentCount: 3,
          findingsBySeverity: { info: 0, low: 0, medium: 0, high: 0, critical: 0 },
        },
      });

      const html = await renderHtml(result, 'en');

      expect(html).toContain('Components with known vulnerabilities');
      expect(html).toContain('Unique known vulnerabilities');
      expect(html).toContain('Outdated components');
      expect(html).toContain('>5<');
      expect(html).toContain('>2<');
      expect(html).toContain('>3<');
    });

    it('omits the counter rows when counters are absent', async () => {
      const html = await renderHtml(baseResult(), 'en');

      expect(html).not.toContain('Unique known vulnerabilities');
    });
  });

  describe('component vulnerability evidence', () => {
    it('renders CVSS, type, fixed-in, description, and references from evidence.raw', async () => {
      const finding = createFinding({
        id: 'f1',
        category: 'security',
        confidence: 'confirmed',
        severity: 'critical',
        sourceLayer: 'third-party',
        businessImpact: 'strong',
        recommendationKey: 'finding.component.plugin.vulnerable.recommendation',
        recommendationParams: { slug: 'akismet' },
        evidence: [
          {
            descriptionKey: 'finding.componentVulnerability.plugin.confirmed.evidence',
            params: { slug: 'akismet', title: 'Some Vuln (CVE-2024-1234)' },
            raw: {
              id: 'v1',
              title: 'Some Vuln',
              fixedIn: '5.1',
              cvssScore: 9.8,
              vulnType: 'XSS',
              description: 'A stored XSS in the admin panel.',
              references: ['CVE-2024-1234', 'https://example.com/advisory'],
            },
          },
        ],
        component: {
          kind: 'plugin',
          slug: 'akismet',
          isOutdated: false,
          vulnerabilitySeverities: ['critical'],
        },
      });

      const html = await renderHtml(baseResult({ findings: [finding] }), 'en');

      expect(html).toContain('CVSS: 9.8');
      expect(html).toContain('Type: XSS');
      expect(html).toContain('Fixed in: 5.1');
      expect(html).toContain('A stored XSS in the admin panel.');
      expect(html).toContain('References:');
      expect(html).toContain('class="badge severity-critical"');
      // Each vulnerability is its own visually distinct card, not a loose paragraph.
      expect(html).toContain('class="vulnerability-card"');
      // The evidence sentence no longer repeats "The {{slug}} plugin ..." — the
      // component's identity is already stated once via the versionInfo line.
      expect(html).toContain('Some Vuln (CVE-2024-1234) — confirmed vulnerability.');
      expect(html).not.toContain('The akismet plugin');
      // A real http(s) reference becomes a clickable link, shown by hostname
      // rather than the full raw URL (which wraps badly).
      expect(html).toContain('<a href="https://example.com/advisory"');
      expect(html).toContain('>example.com</a>');
      // A bare CVE identifier (not a URL) stays plain text, never turned into a synthesized lookup link.
      expect(html).not.toContain('<a href="CVE-2024-1234"');
    });

    it('omits CVSS/type/fixed-in/description/references lines when the data is absent, without fabricating placeholders', async () => {
      const finding = createFinding({
        id: 'f1',
        category: 'security',
        confidence: 'confirmed',
        severity: 'medium',
        sourceLayer: 'third-party',
        businessImpact: 'strong',
        recommendationKey: 'finding.component.plugin.vulnerable.recommendation',
        evidence: [
          {
            descriptionKey: 'finding.componentVulnerability.plugin.confirmed.evidence',
            params: { slug: 'akismet', title: 'Some Vuln' },
            raw: { id: 'v1', title: 'Some Vuln', references: [] },
          },
        ],
        component: {
          kind: 'plugin',
          slug: 'akismet',
          isOutdated: false,
          vulnerabilitySeverities: ['medium'],
        },
      });

      const html = await renderHtml(baseResult({ findings: [finding] }), 'en');

      expect(html).not.toContain('CVSS:');
      expect(html).not.toContain('Fixed in:');
      expect(html).not.toContain('References:');
    });
  });

  describe('component heading', () => {
    function componentFinding(component: ComponentFindingInfo): Finding {
      return createFinding({
        id: 'f1',
        category: 'maintenance',
        confidence: 'corroborated',
        severity: 'medium',
        sourceLayer: 'third-party',
        businessImpact: 'medium',
        recommendationKey: 'finding.component.plugin.outdated.recommendation',
        recommendationParams: { slug: component.slug },
        evidence: [],
        component,
      });
    }

    it('renders a "Plugin: {slug}" heading for a plugin finding', async () => {
      const finding = componentFinding({
        kind: 'plugin',
        slug: 'akismet',
        isOutdated: true,
        vulnerabilitySeverities: [],
      });

      const html = await renderHtml(baseResult({ findings: [finding] }), 'en');

      expect(html).toContain('<h3 class="finding-title">Plugin: akismet</h3>');
    });

    it('renders a "Theme: {slug}" heading for a theme finding', async () => {
      const finding = componentFinding({
        kind: 'theme',
        slug: 'astra',
        isOutdated: true,
        vulnerabilitySeverities: [],
      });

      const html = await renderHtml(baseResult({ findings: [finding] }), 'en');

      expect(html).toContain('<h3 class="finding-title">Theme: astra</h3>');
    });

    it('renders a plain "WordPress Core" heading (no slug) for a core finding', async () => {
      const finding = componentFinding({
        kind: 'core',
        slug: 'wordpress-core',
        isOutdated: true,
        vulnerabilitySeverities: [],
      });

      const html = await renderHtml(baseResult({ findings: [finding] }), 'en');

      expect(html).toContain('<h3 class="finding-title">WordPress Core</h3>');
      expect(html).not.toContain('WordPress Core: wordpress-core');
    });

    it('omits the heading entirely for a non-component finding', async () => {
      const finding = createFinding({
        id: 'f1',
        category: 'security',
        confidence: 'confirmed',
        severity: 'low',
        sourceLayer: 1,
        businessImpact: 'weak',
        recommendationKey: 'finding.header.missingHsts.recommendation',
        evidence: [{ descriptionKey: 'finding.header.missingHsts.evidence' }],
      });

      const html = await renderHtml(baseResult({ findings: [finding] }), 'en');

      expect(html).not.toContain('class="finding-title"');
    });
  });
});
