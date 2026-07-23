import { describe, expect, it } from 'vitest';
import { HeaderScanner } from '@scanners/header-scanner.js';
import { DefaultAuditContext } from '@core/types/audit-context.js';
import { buildTarget } from '@core/types/target.js';
import type { HttpResponse } from '@core/http/http-client.js';

function createContext(headers: Record<string, string>): DefaultAuditContext {
  const context = new DefaultAuditContext({
    target: buildTarget('https://example.com'),
    authorizationMode: 'prospect',
    profile: 'standard',
    startedAt: new Date(0).toISOString(),
  });
  const response: HttpResponse = { url: 'https://example.com/', status: 200, headers, body: '' };
  context.setHttpResponse(response);
  return context;
}

describe('HeaderScanner', () => {
  it('reports present security and info-disclosure headers verbatim', async () => {
    const context = createContext({
      'strict-transport-security': 'max-age=63072000',
      'x-frame-options': 'SAMEORIGIN',
      server: 'Apache/2.4.41',
      'x-powered-by': 'PHP/7.4.3',
    });
    const scanner = new HeaderScanner();

    const result = await scanner.run(context);

    expect(result.status).toBe('ok');
    expect(result.data).toEqual({
      securityHeaders: {
        'strict-transport-security': 'max-age=63072000',
        'content-security-policy': undefined,
        'x-frame-options': 'SAMEORIGIN',
        'x-content-type-options': undefined,
        'referrer-policy': undefined,
        'permissions-policy': undefined,
      },
      infoDisclosureHeaders: {
        server: 'Apache/2.4.41',
        'x-powered-by': 'PHP/7.4.3',
      },
    });
  });

  it('reports all-undefined headers when none are present, without inventing values', async () => {
    const context = createContext({});
    const scanner = new HeaderScanner();

    const result = await scanner.run(context);

    expect(result.data).toEqual({
      securityHeaders: {
        'strict-transport-security': undefined,
        'content-security-policy': undefined,
        'x-frame-options': undefined,
        'x-content-type-options': undefined,
        'referrer-policy': undefined,
        'permissions-policy': undefined,
      },
      infoDisclosureHeaders: {
        server: undefined,
        'x-powered-by': undefined,
      },
    });
  });

  it('supports() is false until the HTTP response has been fetched', () => {
    const context = new DefaultAuditContext({
      target: buildTarget('https://example.com'),
      authorizationMode: 'prospect',
      profile: 'standard',
      startedAt: new Date(0).toISOString(),
    });
    const scanner = new HeaderScanner();

    expect(scanner.supports(context)).toBe(false);
  });
});
