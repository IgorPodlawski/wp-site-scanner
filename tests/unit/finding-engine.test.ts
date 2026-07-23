import { describe, expect, it } from 'vitest';
import {
  generateFindings,
  WORDPRESS_ORG_PLUGIN_ENRICHMENT,
  WORDPRESS_ORG_THEME_ENRICHMENT,
  WORDPRESS_ORG_CORE_ENRICHMENT,
} from '@analysis/finding-engine.js';
import { DefaultAuditContext } from '@core/types/audit-context.js';
import { buildTarget } from '@core/types/target.js';
import type { ScannerResult } from '@core/types/index.js';
import type { HeaderScannerData } from '@scanners/header-scanner.js';
import type { TlsProbeResult } from '@core/http/tls-probe.js';
import type { EndpointScannerData } from '@scanners/endpoint-scanner.js';

function createContext(): DefaultAuditContext {
  return new DefaultAuditContext({
    target: buildTarget('https://example.com'),
    authorizationMode: 'audit',
    profile: 'standard',
    startedAt: new Date(0).toISOString(),
  });
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

  describe('outdated plugins', () => {
    it('flags a plugin older than the wordpress.org latest', () => {
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
        confidence: 'corroborated',
        recommendationKey: 'finding.plugin.outdated.recommendation',
      });
      // recommendationParams must carry {{slug}} — the recommendation message interpolates it
      expect(findings[0]!.recommendationParams).toEqual({ slug: 'akismet' });
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

  describe('outdated themes', () => {
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
        recommendationKey: 'finding.theme.outdated.recommendation',
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

  describe('core version status', () => {
    it('flags an insecure core version as a critical-eligible security finding', () => {
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
        category: 'security',
        severity: 'critical',
        confidence: 'confirmed',
        recommendationKey: 'finding.core.insecure.recommendation',
      });
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
        recommendationKey: 'finding.core.outdated.recommendation',
      });
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
});
