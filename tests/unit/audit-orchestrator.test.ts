import { describe, expect, it, vi } from 'vitest';
import { AuditOrchestrator } from '@core/orchestrator/audit-orchestrator.js';
import type { AuditRequest } from '@core/orchestrator/audit-request.js';
import type { Scanner, ScannerResult } from '@core/types/index.js';
import { SsrfRejectedError } from '@core/errors.js';
import type { AppConfig } from '@config/types.js';
import type { Logger } from '@utils/logger.js';
import { saveAuditResult } from '@storage/json-store.js';
import type { WordPressOrgClient } from '@integrations/wordpress-org-client.js';
import type { WpscanClient } from '@integrations/wpscan-client.js';
import { ok, err } from '@utils/result.js';

vi.mock('@storage/json-store.js', () => ({ saveAuditResult: vi.fn(async () => '/tmp/fake.json') }));

const TEST_CONFIG: AppConfig = {
  AUDIT_CONTACT_URL: 'https://example.com/about-this-scan',
  AUDIT_USER_AGENT: 'wp-audit-test/0.1',
  LOG_LEVEL: 'error',
  CACHE_DIR: './data/cache',
  HTTP_TIMEOUT_MS: 10_000,
  MAX_REDIRECTS: 5,
  MAX_RESPONSE_BYTES: 10_485_760,
  BATCH_CONCURRENCY: 4,
  PER_HOST_DELAY_MS: 1000,
  wpscanEnabled: false,
  pagespeedEnabled: false,
};

const FAKE_LOGGER = { info: () => {}, warn: () => {}, error: () => {} } as unknown as Logger;

function fakeWordPressOrgClient(overrides: Partial<WordPressOrgClient> = {}): WordPressOrgClient {
  return {
    getPluginInfo: async () => ok(undefined),
    getThemeInfo: async () => ok(undefined),
    getCoreStableVersions: async () => ok({}),
    ...overrides,
  } as unknown as WordPressOrgClient;
}

const NO_OP_WORDPRESS_ORG_CLIENT = fakeWordPressOrgClient();

function fakeWpscanClient(overrides: Partial<WpscanClient> = {}): WpscanClient {
  return {
    getPluginVulnerabilities: async () => ok([]),
    getThemeVulnerabilities: async () => ok([]),
    ...overrides,
  } as unknown as WpscanClient;
}

const NO_OP_WPSCAN_CLIENT = fakeWpscanClient();

const PROSPECT_REQUEST: AuditRequest = {
  targetInput: 'https://example.com',
  requestedMode: 'prospect',
  profile: 'standard',
  lang: 'en',
  useCache: true,
};

function fakeScanner(
  name: string,
  overrides: Partial<Scanner> & { run?: Scanner['run'] } = {},
): Scanner {
  return {
    name,
    minAuthorization: 'prospect',
    supports: () => true,
    run: async () => ({ scannerName: name, status: 'ok', durationMs: 0 }) satisfies ScannerResult,
    ...overrides,
  };
}

describe('AuditOrchestrator.run', () => {
  it('runs every scanner, saves the result, and reports completed with no scanner failures', async () => {
    const detector = fakeScanner('wordpress-detector', {
      run: async (context) => {
        context.setDetectedWordPress(true);
        return { scannerName: 'wordpress-detector', status: 'ok', durationMs: 0 };
      },
    });
    const other = fakeScanner('core-version-scanner');
    const orchestrator = new AuditOrchestrator(
      [detector, other],
      TEST_CONFIG,
      FAKE_LOGGER,
      NO_OP_WORDPRESS_ORG_CLIENT,
      NO_OP_WPSCAN_CLIENT,
    );

    const result = await orchestrator.run(PROSPECT_REQUEST);

    expect(result.status).toBe('completed');
    expect(result.isWordPress).toBe(true);
    expect(result.findings).toEqual([]);
    expect(result.scannerResults.map((r) => r.scannerName)).toEqual([
      'wordpress-detector',
      'core-version-scanner',
    ]);
    expect(result.scores?.overall).toBe(100);
    expect(saveAuditResult).toHaveBeenCalledWith(result);
  });

  it('short-circuits after wordpress-detector reports a non-WordPress target', async () => {
    const detector = fakeScanner('wordpress-detector', {
      run: async (context) => {
        context.setDetectedWordPress(false);
        return { scannerName: 'wordpress-detector', status: 'ok', durationMs: 0 };
      },
    });
    const neverRun = fakeScanner('core-version-scanner', {
      run: async () => {
        throw new Error('should never run once WordPress is ruled out');
      },
    });
    const orchestrator = new AuditOrchestrator(
      [detector, neverRun],
      TEST_CONFIG,
      FAKE_LOGGER,
      NO_OP_WORDPRESS_ORG_CLIENT,
      NO_OP_WPSCAN_CLIENT,
    );

    const result = await orchestrator.run(PROSPECT_REQUEST);

    expect(result.status).toBe('completed');
    expect(result.isWordPress).toBe(false);
    expect(result.scannerResults.map((r) => r.scannerName)).toEqual(['wordpress-detector']);
    expect(result.findings).toHaveLength(1);
    expect(result.findings[0]).toMatchObject({
      category: 'infrastructure',
      severity: 'info',
      confidence: 'confirmed',
    });
  });

  it('records a non-target-level scanner error as a limitation and continues, downgrading to partial', async () => {
    const detector = fakeScanner('wordpress-detector', {
      run: async (context) => {
        context.setDetectedWordPress(true);
        return { scannerName: 'wordpress-detector', status: 'ok', durationMs: 0 };
      },
    });
    const failing = fakeScanner('tls-scanner', {
      run: async () => {
        throw new Error('handshake failed');
      },
    });
    const after = fakeScanner('header-scanner');
    const orchestrator = new AuditOrchestrator(
      [detector, failing, after],
      TEST_CONFIG,
      FAKE_LOGGER,
      NO_OP_WORDPRESS_ORG_CLIENT,
      NO_OP_WPSCAN_CLIENT,
    );

    const result = await orchestrator.run(PROSPECT_REQUEST);

    expect(result.status).toBe('partial');
    expect(result.limitations).toEqual(['tls-scanner failed: handshake failed']);
    expect(result.scannerResults.map((r) => r.scannerName)).toEqual([
      'wordpress-detector',
      'tls-scanner',
      'header-scanner',
    ]);
    expect(result.scannerResults[1]).toMatchObject({ status: 'error' });
  });

  it('propagates a target-level AuditFailureError instead of downgrading to partial', async () => {
    const failing = fakeScanner('http-scanner', {
      run: async () => {
        throw new SsrfRejectedError('https://example.com/', 'blocked by SSRF guard');
      },
    });
    const orchestrator = new AuditOrchestrator(
      [failing],
      TEST_CONFIG,
      FAKE_LOGGER,
      NO_OP_WORDPRESS_ORG_CLIENT,
      NO_OP_WPSCAN_CLIENT,
    );

    await expect(orchestrator.run(PROSPECT_REQUEST)).rejects.toThrow(SsrfRejectedError);
  });

  it('persists the consent artifact on an audit-mode run', async () => {
    const detector = fakeScanner('wordpress-detector', {
      run: async (context) => {
        context.setDetectedWordPress(true);
        return { scannerName: 'wordpress-detector', status: 'ok', durationMs: 0 };
      },
    });
    const orchestrator = new AuditOrchestrator(
      [detector],
      TEST_CONFIG,
      FAKE_LOGGER,
      NO_OP_WORDPRESS_ORG_CLIENT,
      NO_OP_WPSCAN_CLIENT,
    );

    const result = await orchestrator.run({
      ...PROSPECT_REQUEST,
      requestedMode: 'audit',
      consent: { confirmed: true, source: 'cli-flag' },
    });

    expect(result.consentArtifact).toMatchObject({
      targetDomain: 'example.com',
      confirmed: true,
      source: 'cli-flag',
    });
  });

  it('enriches detected plugins via WordPress.org and emits an outdated-plugin finding', async () => {
    const detector = fakeScanner('wordpress-detector', {
      run: async (context) => {
        context.setDetectedWordPress(true);
        return { scannerName: 'wordpress-detector', status: 'ok', durationMs: 0 };
      },
    });
    const pluginScanner = fakeScanner('plugin-scanner', {
      run: async () => ({
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
      }),
    });
    const wordPressOrgClient = fakeWordPressOrgClient({
      getPluginInfo: async (slug: string) =>
        slug === 'akismet'
          ? ok({ slug: 'akismet', version: '5.7', lastUpdated: '', activeInstalls: 1 })
          : ok(undefined),
    });
    const orchestrator = new AuditOrchestrator(
      [detector, pluginScanner],
      TEST_CONFIG,
      FAKE_LOGGER,
      wordPressOrgClient,
      NO_OP_WPSCAN_CLIENT,
    );

    const result = await orchestrator.run(PROSPECT_REQUEST);

    expect(result.status).toBe('completed');
    expect(result.findings).toHaveLength(1);
    expect(result.findings[0]).toMatchObject({
      category: 'maintenance',
      confidence: 'corroborated',
      recommendationKey: 'finding.plugin.outdated.recommendation',
    });
  });

  it('downgrades to partial when a WordPress.org lookup fails, without treating it as "not found"', async () => {
    const detector = fakeScanner('wordpress-detector', {
      run: async (context) => {
        context.setDetectedWordPress(true);
        return { scannerName: 'wordpress-detector', status: 'ok', durationMs: 0 };
      },
    });
    const pluginScanner = fakeScanner('plugin-scanner', {
      run: async () => ({
        scannerName: 'plugin-scanner',
        status: 'ok',
        data: { plugins: [{ slug: 'akismet' }] },
        durationMs: 0,
      }),
    });
    const wordPressOrgClient = fakeWordPressOrgClient({
      getPluginInfo: async () => err(new Error('timeout')),
    });
    const orchestrator = new AuditOrchestrator(
      [detector, pluginScanner],
      TEST_CONFIG,
      FAKE_LOGGER,
      wordPressOrgClient,
      NO_OP_WPSCAN_CLIENT,
    );

    const result = await orchestrator.run(PROSPECT_REQUEST);

    expect(result.status).toBe('partial');
    expect(result.limitations).toEqual(['wordpress-org plugin lookup failed for 1 of 1 item(s)']);
  });

  it('never queries WPScan in prospect mode, even when the token is configured', async () => {
    const detector = fakeScanner('wordpress-detector', {
      run: async (context) => {
        context.setDetectedWordPress(true);
        return { scannerName: 'wordpress-detector', status: 'ok', durationMs: 0 };
      },
    });
    const pluginScanner = fakeScanner('plugin-scanner', {
      run: async () => ({
        scannerName: 'plugin-scanner',
        status: 'ok',
        data: { plugins: [{ slug: 'akismet' }] },
        durationMs: 0,
      }),
    });
    const wpscanClient = fakeWpscanClient({
      getPluginVulnerabilities: async () => {
        throw new Error('WPScan must not be queried in prospect mode');
      },
    });
    const orchestrator = new AuditOrchestrator(
      [detector, pluginScanner],
      { ...TEST_CONFIG, wpscanEnabled: true },
      FAKE_LOGGER,
      NO_OP_WORDPRESS_ORG_CLIENT,
      wpscanClient,
    );

    const result = await orchestrator.run(PROSPECT_REQUEST);

    expect(result.status).toBe('completed');
    expect(result.findings).toEqual([]);
  });

  it('queries WPScan in audit mode and asserts a confirmed vulnerability finding', async () => {
    const detector = fakeScanner('wordpress-detector', {
      run: async (context) => {
        context.setDetectedWordPress(true);
        return { scannerName: 'wordpress-detector', status: 'ok', durationMs: 0 };
      },
    });
    const pluginScanner = fakeScanner('plugin-scanner', {
      run: async () => ({
        scannerName: 'plugin-scanner',
        status: 'ok',
        data: {
          plugins: [
            {
              slug: 'akismet',
              version: {
                value: '5.0',
                sources: ['plugin-readme', 'asset-query-string'],
                confidence: 'confirmed',
              },
            },
          ],
        },
        durationMs: 0,
      }),
    });
    const wpscanClient = fakeWpscanClient({
      getPluginVulnerabilities: async (slug: string) =>
        slug === 'akismet'
          ? ok([{ id: '1', title: 'Some XSS', fixedIn: '5.1', references: [] }])
          : ok([]),
    });
    const orchestrator = new AuditOrchestrator(
      [detector, pluginScanner],
      { ...TEST_CONFIG, wpscanEnabled: true },
      FAKE_LOGGER,
      NO_OP_WORDPRESS_ORG_CLIENT,
      wpscanClient,
    );

    const result = await orchestrator.run({
      ...PROSPECT_REQUEST,
      requestedMode: 'audit',
      consent: { confirmed: true, source: 'cli-flag' },
    });

    expect(result.findings).toHaveLength(1);
    expect(result.findings[0]).toMatchObject({
      category: 'security',
      severity: 'critical',
      confidence: 'confirmed',
      recommendationKey: 'finding.plugin.vulnerability.confirmed.recommendation',
    });
  });
});
