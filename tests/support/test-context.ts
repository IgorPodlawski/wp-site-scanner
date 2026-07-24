import { DefaultAuditContext } from '@core/types/audit-context.js';
import { buildTarget } from '@core/types/target.js';
import type { AuthorizationMode, IntensityProfile } from '@core/types/authorization.js';
import type { HttpClientOptions, HttpResponse } from '@core/http/http-client.js';

/** Shared across scanner/finding-engine tests wherever an HttpClientOptions value is needed but its specifics don't matter. */
export const TEST_HTTP_OPTIONS: HttpClientOptions = {
  timeoutMs: 1000,
  maxRedirects: 5,
  maxResponseBytes: 1_000_000,
  userAgent: 'wp-audit-test/0.1',
};

export interface TestContextOverrides {
  target?: string;
  authorizationMode?: AuthorizationMode;
  profile?: IntensityProfile;
}

/** The AuditContext construction repeated (with minor variations) across every scanner test file. */
export function buildTestContext(overrides: TestContextOverrides = {}): DefaultAuditContext {
  return new DefaultAuditContext({
    target: buildTarget(overrides.target ?? 'https://example.com'),
    authorizationMode: overrides.authorizationMode ?? 'prospect',
    profile: overrides.profile ?? 'standard',
    startedAt: new Date(0).toISOString(),
  });
}

/** The HttpResponse literal repeated across every scanner test file — override only what a given test cares about. */
export function buildHttpResponse(
  body: string,
  overrides: Partial<HttpResponse> = {},
): HttpResponse {
  return { url: 'https://example.com/', status: 200, headers: {}, body, ...overrides };
}
