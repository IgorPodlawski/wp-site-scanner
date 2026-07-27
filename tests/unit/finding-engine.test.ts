import { describe, expect, it } from 'vitest';
import {
  generateFindings,
  calculateReportCounters,
  WORDPRESS_ORG_PLUGIN_ENRICHMENT,
  WORDPRESS_ORG_THEME_ENRICHMENT,
  WORDPRESS_ORG_CORE_ENRICHMENT,
  WPSCAN_PLUGIN_ENRICHMENT,
  WPSCAN_CORE_ENRICHMENT,
} from '@analysis/finding-engine.js';
import { createFinding } from '@core/types/finding.js';
import type { DefaultAuditContext } from '@core/types/audit-context.js';
import type { Finding, ScannerResult } from '@core/types/index.js';
import type { HeaderScannerData } from '@scanners/header-scanner.js';
import type { TlsProbeResult } from '@core/http/tls-probe.js';
import type { EndpointScannerData } from '@scanners/endpoint-scanner.js';
import { buildTestContext } from '../support/test-context.js';

function createContext(): DefaultAuditContext {
  return buildTestContext({ authorizationMode: 'audit' });
}

const ALL_HEADERS_PRESENT: HeaderScannerData = {
  securityHeaders: {
    'strict-transport-security': 'max-age=63072000',
    'content-security-policy': "default-src 'self'",
    'x-frame-options': 'SAMEORIGIN',
    'x-content-type-options': 'nosniff',
    'referrer-policy': 'no-referrer',
    'permissions-policy': 'geolocation=()',
  },
  infoDisclosureHeaders: { server: undefined, 'x-powered-by': undefined },
};

const NO_HEADERS: HeaderScannerData = {
  securityHeaders: {
    'strict-transport-security': undefined,
    'content-security-policy': undefined,
    'x-frame-options': undefined,
    'x-content-type-options': undefined,
    'referrer-policy': undefined,
    'permissions-policy': undefined,
  },
  infoDisclosureHeaders: { server: undefined, 'x-powered-by': undefined },
};

function headerResult(data: HeaderScannerData): ScannerResult {
  return { scannerName: 'header-scanner', status: 'ok', data, durationMs: 0 };
}

function tlsResult(data: TlsProbeResult): ScannerResult {
  return { scannerName: 'tls-scanner', status: 'ok', data, durationMs: 0 };
}

function endpointResult(data: EndpointScannerData): ScannerResult {
  return { scannerName: 'endpoint-scanner', status: 'ok', data, durationMs: 0 };
}

const VALID_TLS: TlsProbeResult = { protocol: 'TLSv1.3', authorized: true };
const NO_ENDPOINT_FINDINGS: EndpointScannerData = {
  readme: { exists: false },
  restApiUsers: { exists: false },
  xmlrpc: { enabled: false },
  directoryListing: { listingDetected: false },
  configBackups: [{ path: '/wp-config.old', exists: false }],
};

describe('generateFindings', () => {
  it('returns no findings when nothing was scanned', () => {
    expect(generateFindings(createContext())).toEqual([]);
  });

  describe('missing security headers', () => {
    it('flags each missing header', () => {
      const context = createContext();
      context.addScannerResult(headerResult(NO_HEADERS));

      const findings = generateFindings(context);

      expect(findings.map((f) => f.recommendationKey)).toEqual([
        'finding.header.missingHsts.recommendation',
        'finding.header.missingCsp.recommendation',
        'finding.header.missingXFrameOptions.recommendation',
        'finding.header.missingXContentTypeOptions.recommendation',
      ]);
      expect(findings.every((f) => f.severity === 'low' && f.category === 'security')).toBe(true);
    });

    it('flags nothing when all the checked headers are present', () => {
      const context = createContext();
      context.addScannerResult(headerResult(ALL_HEADERS_PRESENT));

      expect(generateFindings(context)).toEqual([]);
    });
  });

  describe('info-disclosure headers', () => {
    it('flags a present Server/X-Powered-By header', () => {
      const context = createContext();
      context.addScannerResult(
        headerResult({
          ...ALL_HEADERS_PRESENT,
          infoDisclosureHeaders: { server: 'Apache/2.4.41', 'x-powered-by': undefined },
        }),
      );

      const findings = generateFindings(context);

      expect(findings).toHaveLength(1);
      expect(findings[0]).toMatchObject({
        severity: 'info',
        recommendationKey: 'finding.header.infoDisclosure.recommendation',
      });
      // recommendationParams must carry {{header}} — the recommendation message interpolates it
      expect(findings[0]!.recommendationParams).toEqual({ header: 'server' });
      expect(findings[0]!.evidence[0]!.params).toEqual({
        header: 'server',
        value: 'Apache/2.4.41',
      });
    });

    it('flags nothing when Server/X-Powered-By are absent', () => {
      const context = createContext();
      context.addScannerResult(headerResult(ALL_HEADERS_PRESENT));

      expect(generateFindings(context)).toEqual([]);
    });
  });

  describe('TLS certificate validity', () => {
    it('flags an unauthorized/expired certificate', () => {
      const context = createContext();
      context.addScannerResult(
        tlsResult({
          protocol: 'TLSv1.3',
          authorized: false,
          authorizationError: 'CERT_HAS_EXPIRED',
        }),
      );

      const findings = generateFindings(context);

      expect(findings).toHaveLength(1);
      expect(findings[0]).toMatchObject({
        severity: 'high',
        recommendationKey: 'finding.tls.invalidCertificate.recommendation',
      });
    });

    it('flags nothing for a valid, authorized certificate', () => {
      const context = createContext();
      context.addScannerResult(tlsResult(VALID_TLS));

      expect(generateFindings(context)).toEqual([]);
    });
  });

  describe('TLS protocol version', () => {
    it('flags an outdated protocol', () => {
      const context = createContext();
      context.addScannerResult(tlsResult({ protocol: 'TLSv1.1', authorized: true }));

      const findings = generateFindings(context);

      expect(findings).toHaveLength(1);
      expect(findings[0]).toMatchObject({
        severity: 'medium',
        recommendationKey: 'finding.tls.outdatedProtocol.recommendation',
      });
    });

    it('flags nothing for TLSv1.3', () => {
      const context = createContext();
      context.addScannerResult(tlsResult(VALID_TLS));

      expect(generateFindings(context)).toEqual([]);
    });
  });

  describe('REST API user enumeration', () => {
    it('flags exposed usernames', () => {
      const context = createContext();
      context.addScannerResult(
        endpointResult({
          ...NO_ENDPOINT_FINDINGS,
          restApiUsers: { exists: true, usernames: ['admin'] },
        }),
      );

      const findings = generateFindings(context);

      expect(findings).toHaveLength(1);
      expect(findings[0]).toMatchObject({
        severity: 'medium',
        sourceLayer: 2,
        recommendationKey: 'finding.endpoint.userEnumeration.recommendation',
      });
    });

    it('flags nothing when the REST API user list is not accessible', () => {
      const context = createContext();
      context.addScannerResult(endpointResult(NO_ENDPOINT_FINDINGS));

      expect(generateFindings(context)).toEqual([]);
    });
  });

  describe('xmlrpc.php', () => {
    it('flags xmlrpc.php when enabled', () => {
      const context = createContext();
      context.addScannerResult(
        endpointResult({ ...NO_ENDPOINT_FINDINGS, xmlrpc: { enabled: true } }),
      );

      const findings = generateFindings(context);

      expect(findings).toHaveLength(1);
      expect(findings[0]).toMatchObject({
        severity: 'low',
        recommendationKey: 'finding.endpoint.xmlrpcEnabled.recommendation',
      });
    });

    it('flags nothing when xmlrpc.php is disabled', () => {
      const context = createContext();
      context.addScannerResult(endpointResult(NO_ENDPOINT_FINDINGS));

      expect(generateFindings(context)).toEqual([]);
    });
  });

  describe('directory listing', () => {
    it('flags a detected directory listing', () => {
      const context = createContext();
      context.addScannerResult(
        endpointResult({
          ...NO_ENDPOINT_FINDINGS,
          directoryListing: { listingDetected: true },
        }),
      );

      const findings = generateFindings(context);

      expect(findings).toHaveLength(1);
      expect(findings[0]).toMatchObject({
        severity: 'medium',
        recommendationKey: 'finding.endpoint.directoryListing.recommendation',
      });
    });

    it('flags nothing when no listing is detected', () => {
      const context = createContext();
      context.addScannerResult(endpointResult(NO_ENDPOINT_FINDINGS));

      expect(generateFindings(context)).toEqual([]);
    });
  });

  describe('exposed config backups', () => {
    it('flags an exposed wp-config backup as critical', () => {
      const context = createContext();
      context.addScannerResult(
        endpointResult({
          ...NO_ENDPOINT_FINDINGS,
          configBackups: [
            { path: '/wp-config.php.bak', exists: false },
            { path: '/wp-config.old', exists: true },
          ],
        }),
      );

      const findings = generateFindings(context);

      expect(findings).toHaveLength(1);
      expect(findings[0]).toMatchObject({
        severity: 'critical',
        confidence: 'confirmed',
        recommendationKey: 'finding.endpoint.configBackupExposed.recommendation',
      });
      expect(findings[0]!.evidence[0]!.params).toEqual({ paths: '/wp-config.old' });
    });

    it('flags nothing when no config backup is exposed', () => {
      const context = createContext();
      context.addScannerResult(endpointResult(NO_ENDPOINT_FINDINGS));

      expect(generateFindings(context)).toEqual([]);
    });
  });

  it('ignores scanner results that errored instead of treating missing data as a finding', () => {
    const context = createContext();
    context.addScannerResult({
      scannerName: 'header-scanner',
      status: 'error',
      error: { message: 'boom' },
      durationMs: 0,
    });

    expect(generateFindings(context)).toEqual([]);
  });

  describe('outdated plugins (no known vulnerabilities)', () => {
    it('flags a plugin older than the wordpress.org latest as a maintenance finding', () => {
      const context = createContext();
      context.addScannerResult({
        scannerName: 'plugin-scanner',
        status: 'ok',
        data: {
          plugins: [
            {
              slug: 'akismet',
              version: { value: '5.0', sources: ['plugin-readme'], confidence: 'corroborated' },
            },
          ],
        },
        durationMs: 0,
      });
      context.setEnrichment(WORDPRESS_ORG_PLUGIN_ENRICHMENT, {
        akismet: { slug: 'akismet', version: '5.7', lastUpdated: '', activeInstalls: 1 },
      });

      const findings = generateFindings(context);

      expect(findings).toHaveLength(1);
      expect(findings[0]).toMatchObject({
        category: 'maintenance',
        severity: 'medium',
        confidence: 'corroborated',
        recommendationKey: 'finding.component.plugin.outdated.recommendation',
      });
      // recommendationParams must carry {{slug}} — the recommendation message interpolates it
      expect(findings[0]!.recommendationParams).toEqual({ slug: 'akismet' });
      expect(findings[0]!.component).toEqual({
        kind: 'plugin',
        slug: 'akismet',
        isOutdated: true,
        vulnerabilitySeverities: [],
      });
      // Regression: the outdatedStatus evidence template interpolates {{slug}} —
      // it must actually be in params, or the rendered report shows the literal "{{slug}}".
      const outdatedEvidence = findings[0]!.evidence.find(
        (e) => e.descriptionKey === 'finding.component.plugin.outdatedStatus.evidence',
      );
      expect(outdatedEvidence?.params).toEqual({
        slug: 'akismet',
        installed: '5.0',
        latest: '5.7',
      });
    });

    it('flags nothing when the installed version already matches the latest', () => {
      const context = createContext();
      context.addScannerResult({
        scannerName: 'plugin-scanner',
        status: 'ok',
        data: {
          plugins: [
            {
              slug: 'akismet',
              version: { value: '5.7', sources: ['plugin-readme'], confidence: 'corroborated' },
            },
          ],
        },
        durationMs: 0,
      });
      context.setEnrichment(WORDPRESS_ORG_PLUGIN_ENRICHMENT, {
        akismet: { slug: 'akismet', version: '5.7', lastUpdated: '', activeInstalls: 1 },
      });

      expect(generateFindings(context)).toEqual([]);
    });
  });

  describe('plugin vulnerabilities', () => {
    it('resolves severity from CVSS, not from version-detection confidence', () => {
      const context = createContext();
      context.addScannerResult({
        scannerName: 'plugin-scanner',
        status: 'ok',
        data: {
          plugins: [
            {
              // Deliberately 'inferred' — the whole point of this test is that a
              // critical CVSS score must NOT be capped down by weak version confidence.
              slug: 'sitepress-multilingual-cms',
              version: { value: '4.6.11', sources: ['asset-query-string'], confidence: 'inferred' },
            },
          ],
        },
        durationMs: 0,
      });
      context.setEnrichment(WPSCAN_PLUGIN_ENRICHMENT, {
        'sitepress-multilingual-cms': [
          {
            id: 'abc-123',
            title: 'WPML Multilingual CMS < 4.6.13 - Contributor+ RCE',
            fixedIn: '4.6.13',
            cvssScore: 9.8,
            references: ['CVE-2024-1234', 'https://wpscan.com/vulnerability/abc-123'],
          },
        ],
      });

      const findings = generateFindings(context);

      expect(findings).toHaveLength(1);
      expect(findings[0]).toMatchObject({
        category: 'security',
        severity: 'critical',
        confidence: 'inferred',
        recommendationKey: 'finding.component.plugin.vulnerable.recommendation',
      });
      expect(findings[0]!.component).toMatchObject({
        kind: 'plugin',
        slug: 'sitepress-multilingual-cms',
        vulnerabilitySeverities: ['critical'],
      });
      // recommendationParams must carry {{slug}} — the recommendation message interpolates it
      expect(findings[0]!.recommendationParams).toEqual({ slug: 'sitepress-multilingual-cms' });
      const vulnEvidence = findings[0]!.evidence.find((e) =>
        e.descriptionKey.startsWith('finding.componentVulnerability.'),
      );
      expect(vulnEvidence?.descriptionKey).toBe(
        'finding.componentVulnerability.plugin.potential.evidence',
      );
      expect(vulnEvidence?.params).toEqual({
        slug: 'sitepress-multilingual-cms',
        title: 'WPML Multilingual CMS < 4.6.13 - Contributor+ RCE (CVE-2024-1234)',
      });
    });

    it('falls back to medium severity when WPScan provides no CVSS score', () => {
      const context = createContext();
      context.addScannerResult({
        scannerName: 'plugin-scanner',
        status: 'ok',
        data: {
          plugins: [
            {
              slug: 'wordpress-seo',
              version: { value: '23.0', sources: ['plugin-readme'], confidence: 'confirmed' },
            },
          ],
        },
        durationMs: 0,
      });
      context.setEnrichment(WPSCAN_PLUGIN_ENRICHMENT, {
        'wordpress-seo': [
          {
            id: 'seo-1',
            title: 'Yoast SEO < 26.9 - Contributor+ Stored XSS',
            fixedIn: '26.9',
            references: [],
          },
        ],
      });

      const findings = generateFindings(context);

      expect(findings[0]).toMatchObject({ severity: 'medium', confidence: 'confirmed' });
    });

    it('marks a vulnerability "confirmed" only when applicable and the version is confirmed, else "potential"', () => {
      const context = createContext();
      context.addScannerResult({
        scannerName: 'plugin-scanner',
        status: 'ok',
        data: {
          plugins: [
            {
              slug: 'wordpress-seo',
              version: { value: '23.0', sources: ['plugin-readme'], confidence: 'corroborated' },
            },
          ],
        },
        durationMs: 0,
      });
      context.setEnrichment(WPSCAN_PLUGIN_ENRICHMENT, {
        'wordpress-seo': [
          {
            id: 'seo-1',
            title: 'Yoast SEO < 26.9 - Contributor+ Stored XSS',
            fixedIn: '26.9',
            cvssScore: 6.1,
            references: [],
          },
        ],
      });

      const findings = generateFindings(context);
      const vulnEvidence = findings[0]!.evidence.find((e) =>
        e.descriptionKey.startsWith('finding.componentVulnerability.'),
      );

      expect(findings[0]!.severity).toBe('medium');
      expect(vulnEvidence?.descriptionKey).toBe(
        'finding.componentVulnerability.plugin.potential.evidence',
      );
    });

    it('does not append anything to the title when WPScan assigned no CVE id', () => {
      const context = createContext();
      context.addScannerResult({
        scannerName: 'plugin-scanner',
        status: 'ok',
        data: {
          plugins: [
            {
              slug: 'akismet',
              version: { value: '5.0', sources: ['plugin-readme'], confidence: 'confirmed' },
            },
          ],
        },
        durationMs: 0,
      });
      context.setEnrichment(WPSCAN_PLUGIN_ENRICHMENT, {
        akismet: [
          {
            id: 'no-cve',
            title: 'Akismet - Some Issue',
            references: ['https://wpscan.com/vulnerability/no-cve'],
          },
        ],
      });

      const findings = generateFindings(context);
      const vulnEvidence = findings[0]!.evidence.find((e) =>
        e.descriptionKey.startsWith('finding.componentVulnerability.'),
      );

      expect(vulnEvidence?.params).toMatchObject({ title: 'Akismet - Some Issue' });
    });

    it('does not flag a vulnerability the installed version has already moved past', () => {
      const context = createContext();
      context.addScannerResult({
        scannerName: 'plugin-scanner',
        status: 'ok',
        data: {
          plugins: [
            {
              slug: 'akismet',
              version: { value: '5.7', sources: ['plugin-readme'], confidence: 'confirmed' },
            },
          ],
        },
        durationMs: 0,
      });
      context.setEnrichment(WPSCAN_PLUGIN_ENRICHMENT, {
        akismet: [{ id: 'old-1', title: 'Old fixed issue', fixedIn: '5.5', references: [] }],
      });

      expect(generateFindings(context)).toEqual([]);
    });

    it('merges outdated status and vulnerabilities for the same plugin into one finding, not two', () => {
      const context = createContext();
      context.addScannerResult({
        scannerName: 'plugin-scanner',
        status: 'ok',
        data: {
          plugins: [
            {
              slug: 'akismet',
              version: { value: '5.0', sources: ['plugin-readme'], confidence: 'confirmed' },
            },
          ],
        },
        durationMs: 0,
      });
      context.setEnrichment(WORDPRESS_ORG_PLUGIN_ENRICHMENT, {
        akismet: { slug: 'akismet', version: '5.7', lastUpdated: '', activeInstalls: 1 },
      });
      context.setEnrichment(WPSCAN_PLUGIN_ENRICHMENT, {
        akismet: [
          { id: 'v1', title: 'Some issue', fixedIn: '5.1', cvssScore: 7.5, references: [] },
        ],
      });

      const findings = generateFindings(context);

      expect(findings).toHaveLength(1);
      expect(findings[0]).toMatchObject({ category: 'security', severity: 'high' });
      expect(findings[0]!.component).toEqual({
        kind: 'plugin',
        slug: 'akismet',
        isOutdated: true,
        vulnerabilitySeverities: ['high'],
      });
    });
  });

  describe('outdated themes (no known vulnerabilities)', () => {
    it('flags a theme older than the wordpress.org latest', () => {
      const context = createContext();
      context.addScannerResult({
        scannerName: 'theme-scanner',
        status: 'ok',
        data: {
          themes: [
            {
              slug: 'twentytwentyfour',
              version: { value: '1.0', sources: ['theme-stylesheet'], confidence: 'corroborated' },
            },
          ],
        },
        durationMs: 0,
      });
      context.setEnrichment(WORDPRESS_ORG_THEME_ENRICHMENT, {
        twentytwentyfour: {
          slug: 'twentytwentyfour',
          version: '1.5',
          lastUpdated: '',
          activeInstalls: 1,
        },
      });

      const findings = generateFindings(context);

      expect(findings).toHaveLength(1);
      expect(findings[0]).toMatchObject({
        category: 'maintenance',
        recommendationKey: 'finding.component.theme.outdated.recommendation',
      });
    });

    it('flags nothing when the theme is not known to wordpress.org', () => {
      const context = createContext();
      context.addScannerResult({
        scannerName: 'theme-scanner',
        status: 'ok',
        data: {
          themes: [
            {
              slug: 'custom-theme',
              version: { value: '1.0', sources: ['theme-stylesheet'], confidence: 'corroborated' },
            },
          ],
        },
        durationMs: 0,
      });
      context.setEnrichment(WORDPRESS_ORG_THEME_ENRICHMENT, { 'custom-theme': undefined });

      expect(generateFindings(context)).toEqual([]);
    });
  });

  describe('core version status (no itemized vulnerabilities)', () => {
    it('flags an insecure core version as a maintenance finding when WPScan has no itemized data for it', () => {
      // Severity comes from vulnerability data, never from wordpress.org's coarse
      // status flag alone — the distinction between "insecure" and "outdated"
      // still shows up in the evidence text, just not in severity/category.
      const context = createContext();
      context.addScannerResult({
        scannerName: 'core-version-scanner',
        status: 'ok',
        data: {
          version: {
            value: '6.4',
            sources: ['generator-meta', 'asset-query-string'],
            confidence: 'confirmed',
          },
        },
        durationMs: 0,
      });
      context.setEnrichment(WORDPRESS_ORG_CORE_ENRICHMENT, {
        '6.4': 'insecure',
        '7.0.2': 'latest',
      });

      const findings = generateFindings(context);

      expect(findings).toHaveLength(1);
      expect(findings[0]).toMatchObject({
        category: 'maintenance',
        severity: 'medium',
        confidence: 'confirmed',
        recommendationKey: 'finding.component.core.outdated.recommendation',
      });
      expect(
        findings[0]!.evidence.some(
          (e) => e.descriptionKey === 'finding.component.core.insecureStatus.evidence',
        ),
      ).toBe(true);
    });

    it('flags an outdated (but not insecure) core version as a maintenance finding', () => {
      const context = createContext();
      context.addScannerResult({
        scannerName: 'core-version-scanner',
        status: 'ok',
        data: {
          version: { value: '7.0.1', sources: ['generator-meta'], confidence: 'corroborated' },
        },
        durationMs: 0,
      });
      context.setEnrichment(WORDPRESS_ORG_CORE_ENRICHMENT, {
        '7.0.1': 'outdated',
        '7.0.2': 'latest',
      });

      const findings = generateFindings(context);

      expect(findings).toHaveLength(1);
      expect(findings[0]).toMatchObject({
        category: 'maintenance',
        severity: 'medium',
        recommendationKey: 'finding.component.core.outdated.recommendation',
      });
      expect(
        findings[0]!.evidence.some(
          (e) => e.descriptionKey === 'finding.component.core.outdatedStatus.evidence',
        ),
      ).toBe(true);
    });

    it('flags nothing when the installed version is the latest', () => {
      const context = createContext();
      context.addScannerResult({
        scannerName: 'core-version-scanner',
        status: 'ok',
        data: {
          version: { value: '7.0.2', sources: ['generator-meta'], confidence: 'corroborated' },
        },
        durationMs: 0,
      });
      context.setEnrichment(WORDPRESS_ORG_CORE_ENRICHMENT, { '7.0.2': 'latest' });

      expect(generateFindings(context)).toEqual([]);
    });

    it('flags nothing when the installed version is absent from the stable-check map', () => {
      const context = createContext();
      context.addScannerResult({
        scannerName: 'core-version-scanner',
        status: 'ok',
        data: {
          version: { value: '99.0', sources: ['generator-meta'], confidence: 'corroborated' },
        },
        durationMs: 0,
      });
      context.setEnrichment(WORDPRESS_ORG_CORE_ENRICHMENT, { '7.0.2': 'latest' });

      expect(generateFindings(context)).toEqual([]);
    });
  });

  describe('core vulnerabilities', () => {
    it('resolves severity from CVSS, not from version-detection confidence', () => {
      const context = createContext();
      context.addScannerResult({
        scannerName: 'core-version-scanner',
        status: 'ok',
        data: {
          version: { value: '6.5.4', sources: ['asset-query-string'], confidence: 'inferred' },
        },
        durationMs: 0,
      });
      context.setEnrichment(WPSCAN_CORE_ENRICHMENT, [
        {
          id: 'core-1',
          title: 'WordPress < 6.5.5 - Contributor+ Stored XSS',
          fixedIn: '6.5.5',
          cvssScore: 9.8,
          references: ['CVE-2024-9999'],
        },
      ]);

      const findings = generateFindings(context);

      expect(findings).toHaveLength(1);
      expect(findings[0]).toMatchObject({
        category: 'security',
        severity: 'critical',
        confidence: 'inferred',
        recommendationKey: 'finding.component.core.vulnerable.recommendation',
      });
      const vulnEvidence = findings[0]!.evidence.find((e) =>
        e.descriptionKey.startsWith('finding.componentVulnerability.'),
      );
      expect(vulnEvidence?.descriptionKey).toBe(
        'finding.componentVulnerability.core.potential.evidence',
      );
      expect(vulnEvidence?.params).toEqual({
        slug: 'wordpress-core',
        title: 'WordPress < 6.5.5 - Contributor+ Stored XSS (CVE-2024-9999)',
      });
    });

    it('falls back to medium severity when WPScan provides no CVSS score', () => {
      const context = createContext();
      context.addScannerResult({
        scannerName: 'core-version-scanner',
        status: 'ok',
        data: {
          version: { value: '6.5.4', sources: ['generator-meta'], confidence: 'confirmed' },
        },
        durationMs: 0,
      });
      context.setEnrichment(WPSCAN_CORE_ENRICHMENT, [
        { id: 'core-1', title: 'Some core issue', fixedIn: '6.5.5', references: [] },
      ]);

      const findings = generateFindings(context);

      expect(findings[0]).toMatchObject({ severity: 'medium', confidence: 'confirmed' });
    });

    it('does not flag a core vulnerability the installed version has already moved past', () => {
      const context = createContext();
      context.addScannerResult({
        scannerName: 'core-version-scanner',
        status: 'ok',
        data: {
          version: { value: '6.5.5', sources: ['generator-meta'], confidence: 'confirmed' },
        },
        durationMs: 0,
      });
      context.setEnrichment(WPSCAN_CORE_ENRICHMENT, [
        { id: 'core-1', title: 'Old fixed issue', fixedIn: '6.5.5', references: [] },
      ]);

      expect(generateFindings(context)).toEqual([]);
    });
  });

  describe('component finding grouping', () => {
    it('takes the max severity across multiple applicable vulnerabilities for the same component', () => {
      const context = createContext();
      context.addScannerResult({
        scannerName: 'plugin-scanner',
        status: 'ok',
        data: {
          plugins: [
            {
              slug: 'akismet',
              version: { value: '5.0', sources: ['plugin-readme'], confidence: 'confirmed' },
            },
          ],
        },
        durationMs: 0,
      });
      context.setEnrichment(WPSCAN_PLUGIN_ENRICHMENT, {
        akismet: [
          { id: 'v1', title: 'Low issue', fixedIn: '5.1', cvssScore: 2.0, references: [] },
          { id: 'v2', title: 'Critical issue', fixedIn: '5.1', cvssScore: 9.9, references: [] },
          { id: 'v3', title: 'Medium issue', fixedIn: '5.1', cvssScore: 5.0, references: [] },
        ],
      });

      const findings = generateFindings(context);

      expect(findings).toHaveLength(1);
      expect(findings[0]!.severity).toBe('critical');
      expect(findings[0]!.component?.vulnerabilitySeverities).toEqual([
        'low',
        'critical',
        'medium',
      ]);
    });

    it('deduplicates vulnerabilities sharing the same CVE before listing them as evidence', () => {
      const context = createContext();
      context.addScannerResult({
        scannerName: 'plugin-scanner',
        status: 'ok',
        data: {
          plugins: [
            {
              slug: 'akismet',
              version: { value: '5.0', sources: ['plugin-readme'], confidence: 'confirmed' },
            },
          ],
        },
        durationMs: 0,
      });
      context.setEnrichment(WPSCAN_PLUGIN_ENRICHMENT, {
        akismet: [
          { id: 'v1', title: 'Same issue (v1)', fixedIn: '5.1', references: ['CVE-2024-1111'] },
          { id: 'v2', title: 'Same issue (v2)', fixedIn: '5.1', references: ['CVE-2024-1111'] },
        ],
      });

      const findings = generateFindings(context);
      const vulnEvidenceCount = findings[0]!.evidence.filter((e) =>
        e.descriptionKey.startsWith('finding.componentVulnerability.'),
      ).length;

      expect(vulnEvidenceCount).toBe(1);
      expect(findings[0]!.component?.vulnerabilitySeverities).toHaveLength(1);
    });
  });
});

describe('calculateReportCounters', () => {
  function vulnEvidence(id: string, title: string, references: string[] = []) {
    return {
      descriptionKey: 'finding.componentVulnerability.plugin.confirmed.evidence',
      params: { slug: 'x', title },
      raw: { id, title, references },
    };
  }

  it('counts components with vulnerabilities, unique vulnerabilities (deduped across components), outdated components, and findings by severity', () => {
    const pluginFinding = createFinding({
      id: 'f1',
      category: 'security',
      confidence: 'confirmed',
      severity: 'critical',
      sourceLayer: 'third-party',
      businessImpact: 'strong',
      recommendationKey: 'finding.component.plugin.vulnerable.recommendation',
      evidence: [vulnEvidence('v1', 'Vuln A', ['CVE-2024-1111']), vulnEvidence('v2', 'Vuln B')],
      component: {
        kind: 'plugin',
        slug: 'akismet',
        isOutdated: false,
        vulnerabilitySeverities: ['critical', 'medium'],
      },
    });
    // Shares CVE-2024-1111 with the plugin's Vuln A — must collapse to one in the unique count.
    const coreFinding = createFinding({
      id: 'f2',
      category: 'security',
      confidence: 'confirmed',
      severity: 'high',
      sourceLayer: 'third-party',
      businessImpact: 'strong',
      recommendationKey: 'finding.component.core.vulnerable.recommendation',
      evidence: [vulnEvidence('v3', 'Vuln A (core)', ['CVE-2024-1111'])],
      component: {
        kind: 'core',
        slug: 'wordpress-core',
        isOutdated: false,
        vulnerabilitySeverities: ['high'],
      },
    });
    const themeFinding = createFinding({
      id: 'f3',
      category: 'maintenance',
      confidence: 'corroborated',
      severity: 'medium',
      sourceLayer: 'third-party',
      businessImpact: 'medium',
      recommendationKey: 'finding.component.theme.outdated.recommendation',
      evidence: [],
      component: {
        kind: 'theme',
        slug: 'twentytwentyfour',
        isOutdated: true,
        vulnerabilitySeverities: [],
      },
    });
    const headerFinding = createFinding({
      id: 'f4',
      category: 'security',
      confidence: 'confirmed',
      severity: 'low',
      sourceLayer: 1,
      businessImpact: 'weak',
      recommendationKey: 'finding.header.missingHsts.recommendation',
      evidence: [],
    });

    const counters = calculateReportCounters([
      pluginFinding,
      coreFinding,
      themeFinding,
      headerFinding,
    ]);

    expect(counters).toEqual({
      componentsWithVulnerabilities: 2,
      uniqueVulnerabilityCount: 2, // Vuln A (shared CVE) + Vuln B
      outdatedComponentCount: 1,
      findingsBySeverity: { info: 0, low: 1, medium: 1, high: 1, critical: 1 },
    });
  });

  it('returns all zeros for an empty findings list', () => {
    expect(calculateReportCounters([])).toEqual({
      componentsWithVulnerabilities: 0,
      uniqueVulnerabilityCount: 0,
      outdatedComponentCount: 0,
      findingsBySeverity: { info: 0, low: 0, medium: 0, high: 0, critical: 0 },
    });
  });

  it('ignores non-component findings entirely for component-shaped counters', () => {
    const findings: Finding[] = [
      createFinding({
        id: 'f1',
        category: 'security',
        confidence: 'confirmed',
        severity: 'high',
        sourceLayer: 1,
        businessImpact: 'medium',
        recommendationKey: 'finding.tls.invalidCertificate.recommendation',
        evidence: [],
      }),
    ];

    const counters = calculateReportCounters(findings);

    expect(counters.componentsWithVulnerabilities).toBe(0);
    expect(counters.outdatedComponentCount).toBe(0);
    expect(counters.uniqueVulnerabilityCount).toBe(0);
    expect(counters.findingsBySeverity.high).toBe(1);
  });
});
