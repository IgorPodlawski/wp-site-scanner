import { describe, expect, it } from 'vitest';
import { filterScannersByAuthorization } from '@core/orchestrator/audit-orchestrator.js';
import { ALL_SCANNERS } from '@scanners/scanner-registry.js';
import type { Scanner } from '@core/types/index.js';

describe('ALL_SCANNERS', () => {
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
