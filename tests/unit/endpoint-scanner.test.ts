import { describe, expect, it } from 'vitest';
import { EndpointScanner } from '@scanners/endpoint-scanner.js';
import { DefaultAuditContext } from '@core/types/audit-context.js';
import { buildTarget } from '@core/types/target.js';
import type { HttpClient, HttpClientOptions, HttpResponse } from '@core/http/http-client.js';

const OPTIONS: HttpClientOptions = {
  timeoutMs: 1000,
  maxRedirects: 5,
  maxResponseBytes: 1_000_000,
  userAgent: 'wp-audit-test/0.1',
};

function createContext(): DefaultAuditContext {
  const context = new DefaultAuditContext({
    target: buildTarget('https://example.com'),
    authorizationMode: 'audit',
    profile: 'standard',
    startedAt: new Date(0).toISOString(),
  });
  const response: HttpResponse = {
    url: 'https://example.com/',
    status: 200,
    headers: {},
    body: '<html></html>',
  };
  context.setHttpResponse(response);
  context.setDetectedWordPress(true);
  return context;
}

function fakeClient(responses: Record<string, HttpResponse | Error>): HttpClient {
  return {
    fetchUrl: async (url) => {
      const path = new URL(url).pathname;
      const entry = responses[path];
      if (entry instanceof Error) throw entry;
      if (entry) return entry;
      return { url, status: 404, headers: {}, body: 'Not Found' };
    },
  };
}

function ok(body: string): HttpResponse {
  return { url: '', status: 200, headers: {}, body };
}

describe('EndpointScanner', () => {
  it('reports each endpoint as absent when every probe 404s', async () => {
    const scanner = new EndpointScanner(OPTIONS, fakeClient({}));
    const result = await scanner.run(createContext());

    expect(result.data).toEqual({
      readme: { exists: false },
      restApiUsers: { exists: false },
      xmlrpc: { enabled: false },
      directoryListing: { listingDetected: false },
      configBackups: [
        { path: '/wp-config.php.bak', exists: false },
        { path: '/wp-config.php~', exists: false },
        { path: '/wp-config.php.save', exists: false },
        { path: '/wp-config.old', exists: false },
      ],
    });
  });

  it('detects readme.html and a config backup when present', async () => {
    const scanner = new EndpointScanner(
      OPTIONS,
      fakeClient({
        '/readme.html': ok('<html>WordPress</html>'),
        '/wp-config.old': ok('<?php // leaked'),
      }),
    );

    const result = await scanner.run(createContext());

    expect(result.data).toMatchObject({
      readme: { exists: true },
      configBackups: [
        { path: '/wp-config.php.bak', exists: false },
        { path: '/wp-config.php~', exists: false },
        { path: '/wp-config.php.save', exists: false },
        { path: '/wp-config.old', exists: true },
      ],
    });
  });

  it('extracts usernames when the REST API user list is publicly exposed', async () => {
    const scanner = new EndpointScanner(
      OPTIONS,
      fakeClient({
        '/wp-json/wp/v2/users': ok(JSON.stringify([{ id: 1, slug: 'admin', name: 'Admin' }])),
      }),
    );

    const result = await scanner.run(createContext());

    expect(result.data).toMatchObject({
      restApiUsers: { exists: true, usernames: ['admin'] },
    });
  });

  it('detects xmlrpc.php only when the response matches the known WordPress reply', async () => {
    const scanner = new EndpointScanner(
      OPTIONS,
      fakeClient({
        '/xmlrpc.php': ok('XML-RPC server accepts POST requests only.'),
      }),
    );

    const result = await scanner.run(createContext());

    expect(result.data).toMatchObject({ xmlrpc: { enabled: true } });
  });

  it('detects a directory listing page', async () => {
    const scanner = new EndpointScanner(
      OPTIONS,
      fakeClient({
        '/wp-content/uploads/': ok('<title>Index of /wp-content/uploads</title>'),
      }),
    );

    const result = await scanner.run(createContext());

    expect(result.data).toMatchObject({ directoryListing: { listingDetected: true } });
  });

  it('records a probe failure without letting it take down the other probes', async () => {
    const scanner = new EndpointScanner(
      OPTIONS,
      fakeClient({
        '/readme.html': new Error('connection reset'),
        '/xmlrpc.php': ok('XML-RPC server accepts POST requests only.'),
      }),
    );

    const result = await scanner.run(createContext());

    expect(result.status).toBe('ok');
    expect(result.data).toMatchObject({
      readme: { exists: false, error: 'connection reset' },
      xmlrpc: { enabled: true },
    });
  });
});
