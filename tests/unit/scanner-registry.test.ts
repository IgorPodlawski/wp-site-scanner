import { describe, expect, it } from 'vitest';
import { filterScannersByAuthorization } from '@core/orchestrator/audit-orchestrator.js';
import { createScanners } from '@scanners/scanner-registry.js';
import type { Scanner } from '@core/types/index.js';
import type { AppConfig } from '@config/types.js';

const TEST_CONFIG: AppConfig = {
  AUDIT_CONTACT_URL: 'https://example.com/about-this-scan',
  AUDIT_USER_AGENT: 'wp-audit-test/0.1 (+https://example.com/about-this-scan)',
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

const ALL_SCANNERS = createScanners(TEST_CONFIG);

describe('createScanners', () => {
  it('every registered scanner declares a valid minAuthorization', () => {
    for (const scanner of ALL_SCANNERS) {
      expect(['prospect', 'audit']).toContain(scanner.minAuthorization);
    }
  });
});

describe('filterScannersByAuthorization', () => {
  it('excludes audit-only scanners under prospect mode', () => {
    const filtered = filterScannersByAuthorization(ALL_SCANNERS, 'prospect');
    expect(filtered.every((scanner) => scanner.minAuthorization === 'prospect')).toBe(true);
    expect(filtered.some((scanner) => scanner.name === 'endpoint-scanner')).toBe(false);
  });

  it('includes audit-only scanners under audit mode', () => {
    const filtered = filterScannersByAuthorization(ALL_SCANNERS, 'audit');
    expect(filtered.some((scanner) => scanner.name === 'endpoint-scanner')).toBe(true);
  });

  it('never runs an audit-only scanner even if called directly under prospect', () => {
    const auditOnly: Scanner = ALL_SCANNERS.find((s) => s.minAuthorization === 'audit')!;
    const filtered = filterScannersByAuthorization([auditOnly], 'prospect');
    expect(filtered).toHaveLength(0);
  });
});
