import type { AuditContext, Scanner, ScannerResult } from '../core/types/index.js';
import type { HttpResponse } from '../core/http/http-client.js';

const SECURITY_HEADERS = [
  'strict-transport-security',
  'content-security-policy',
  'x-frame-options',
  'x-content-type-options',
  'referrer-policy',
  'permissions-policy',
] as const;

const INFO_DISCLOSURE_HEADERS = ['server', 'x-powered-by'] as const;

export type SecurityHeaderName = (typeof SECURITY_HEADERS)[number];
export type InfoDisclosureHeaderName = (typeof INFO_DISCLOSURE_HEADERS)[number];

export interface HeaderScannerData {
  securityHeaders: Record<SecurityHeaderName, string | undefined>;
  infoDisclosureHeaders: Record<InfoDisclosureHeaderName, string | undefined>;
}

/** Checks HTTP security headers (CSP, HSTS, X-Frame-Options, etc.) from the already-fetched response. */
export class HeaderScanner implements Scanner {
  readonly name = 'header-scanner';
  readonly minAuthorization = 'prospect' as const;

  supports(context: AuditContext): boolean {
    return context.getHttpResponse() !== undefined;
  }

  async run(context: AuditContext): Promise<ScannerResult> {
    const startedAt = Date.now();
    const response = context.getHttpResponse() as HttpResponse;

    const securityHeaders = this.pickHeaders(response, SECURITY_HEADERS);
    const infoDisclosureHeaders = this.pickHeaders(response, INFO_DISCLOSURE_HEADERS);

    return {
      scannerName: this.name,
      status: 'ok',
      data: { securityHeaders, infoDisclosureHeaders },
      durationMs: Date.now() - startedAt,
    };
  }

  private pickHeaders<Name extends string>(
    response: HttpResponse,
    names: readonly Name[],
  ): Record<Name, string | undefined> {
    const picked = {} as Record<Name, string | undefined>;
    for (const name of names) {
      picked[name] = response.headers[name];
    }
    return picked;
  }
}
