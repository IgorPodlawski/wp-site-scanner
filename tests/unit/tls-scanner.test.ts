import { describe, expect, it } from 'vitest';
import { TlsScanner } from '@scanners/tls-scanner.js';
import type { DefaultAuditContext } from '@core/types/audit-context.js';
import { SsrfRejectedError } from '@core/errors.js';
import type { TlsProbe, TlsProbeOptions, TlsProbeResult } from '@core/http/tls-probe.js';
import { buildTestContext, buildHttpResponse } from '../support/test-context.js';

function createContext(targetInput: string): DefaultAuditContext {
  return buildTestContext({ target: targetInput });
}

const VALID_RESULT: TlsProbeResult = {
  protocol: 'TLSv1.3',
  authorized: true,
  validFrom: 'Jan 1 00:00:00 2026 GMT',
  validTo: 'Dec 31 23:59:59 2026 GMT',
  subject: 'example.com',
  issuer: "Let's Encrypt",
};

describe('TlsScanner', () => {
  it('probes the resolved, SSRF-validated address while keeping the hostname for SNI', async () => {
    let receivedOptions: TlsProbeOptions | undefined;
    const probe: TlsProbe = {
      probe: async (options) => {
        receivedOptions = options;
        return VALID_RESULT;
      },
    };
    const scanner = new TlsScanner(1000, probe, async () => ['203.0.113.10']);
    const context = createContext('https://example.com');

    const result = await scanner.run(context);

    expect(receivedOptions).toEqual({
      hostname: 'example.com',
      resolvedIp: '203.0.113.10',
      port: 443,
      timeoutMs: 1000,
    });
    expect(result.status).toBe('ok');
    expect(result.data).toEqual(VALID_RESULT);
  });

  it('reports an unauthorized/expired certificate as an observation rather than failing', async () => {
    const expired: TlsProbeResult = {
      protocol: 'TLSv1.2',
      authorized: false,
      authorizationError: 'CERT_HAS_EXPIRED',
      validFrom: 'Jan 1 00:00:00 2020 GMT',
      validTo: 'Jan 1 00:00:00 2021 GMT',
    };
    const probe: TlsProbe = { probe: async () => expired };
    const scanner = new TlsScanner(1000, probe, async () => ['203.0.113.10']);
    const context = createContext('https://example.com');

    const result = await scanner.run(context);

    expect(result.status).toBe('ok');
    expect(result.data).toEqual(expired);
  });

  it('rejects when the hostname resolves to a blocked address (DNS rebinding)', async () => {
    const probe: TlsProbe = {
      probe: async () => {
        throw new Error('probe should not have been called');
      },
    };
    const scanner = new TlsScanner(1000, probe, async () => ['10.0.0.5']);
    const context = createContext('https://example.com');

    await expect(scanner.run(context)).rejects.toThrow(SsrfRejectedError);
  });

  it('supports() is false for a plain http:// target (nothing to probe)', () => {
    const scanner = new TlsScanner(1000, { probe: async () => VALID_RESULT });
    const context = createContext('http://example.com');

    expect(scanner.supports(context)).toBe(false);
  });

  it('supports() is true for an https:// target', () => {
    const scanner = new TlsScanner(1000, { probe: async () => VALID_RESULT });
    const context = createContext('https://example.com');

    expect(scanner.supports(context)).toBe(true);
  });

  it('supports() is true for an http:// target that redirects to https (effective URL, not the raw input)', () => {
    const scanner = new TlsScanner(1000, { probe: async () => VALID_RESULT });
    const context = createContext('http://example.com');
    context.setHttpResponse(buildHttpResponse('', { url: 'https://example.com/' }));

    expect(scanner.supports(context)).toBe(true);
  });

  it('probes the effective (post-redirect) hostname, not the original http:// input', async () => {
    let receivedOptions: TlsProbeOptions | undefined;
    const probe: TlsProbe = {
      probe: async (options) => {
        receivedOptions = options;
        return VALID_RESULT;
      },
    };
    const scanner = new TlsScanner(1000, probe, async () => ['203.0.113.10']);
    const context = createContext('http://example.com');
    context.setHttpResponse(buildHttpResponse('', { url: 'https://example.com/' }));

    await scanner.run(context);

    expect(receivedOptions?.port).toBe(443);
  });
});
