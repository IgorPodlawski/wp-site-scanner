import type { AuditContext, Scanner, ScannerResult } from '../core/types/index.js';
import {
  resolveAndValidateAddress,
  defaultResolveHostname,
  type HttpResponse,
  type ResolveHostname,
} from '../core/http/http-client.js';
import { NodeTlsProbe, type TlsProbe } from '../core/http/tls-probe.js';
import { UnreachableTargetError } from '../core/errors.js';

const DEFAULT_TLS_PORT = 443;

/**
 * The *effective* URL after redirects, not the raw CLI input — a site that
 * redirects `http://` to `https://` still has HTTPS to probe, but
 * `context.target.normalizedUrl` stays `http:` forever (it's the original
 * input, never updated). Without this, such a site's TLS never got probed
 * at all. Falls back to the raw input when the homepage hasn't been fetched
 * yet (shouldn't happen in practice — http-scanner always runs first).
 */
export function effectiveUrl(context: AuditContext): string {
  const response = context.getHttpResponse() as HttpResponse | undefined;
  return response?.url ?? context.target.normalizedUrl;
}

/** Checks TLS configuration (protocol version, certificate validity/expiry) via a direct handshake. */
export class TlsScanner implements Scanner {
  readonly name = 'tls-scanner';
  readonly minAuthorization = 'prospect' as const;

  constructor(
    private readonly timeoutMs: number,
    private readonly probe: TlsProbe = new NodeTlsProbe(),
    private readonly resolveHostname: ResolveHostname = defaultResolveHostname,
  ) {}

  supports(context: AuditContext): boolean {
    return new URL(effectiveUrl(context)).protocol === 'https:';
  }

  async run(context: AuditContext): Promise<ScannerResult> {
    const startedAt = Date.now();
    const url = new URL(effectiveUrl(context));

    // A plain connection failure here is scoped to *this scanner's own* TLS
    // probe on port 443 — it does not mean the target itself is unreachable
    // (the homepage was already fetched successfully via a completely
    // different path to get here at all). Caught and degraded to a
    // scanner-level error rather than left to propagate as
    // UnreachableTargetError, which is an AuditFailureError and would
    // otherwise fail the *entire* audit — found live: a site that redirects
    // http->https but doesn't accept a direct TLS connection on 443 crashed
    // the whole run. SsrfRejectedError (DNS rebinding between the earlier
    // fetch and this probe) deliberately still propagates as fatal — that's
    // a genuine security-relevant refusal, not a mere connectivity hiccup.
    try {
      const resolvedIp = await resolveAndValidateAddress(url, this.resolveHostname);
      const port = url.port ? Number(url.port) : DEFAULT_TLS_PORT;
      const result = await this.probe.probe({
        hostname: url.hostname,
        resolvedIp,
        port,
        timeoutMs: this.timeoutMs,
      });

      return {
        scannerName: this.name,
        status: 'ok',
        data: result,
        durationMs: Date.now() - startedAt,
      };
    } catch (error) {
      if (!(error instanceof UnreachableTargetError)) {
        throw error;
      }
      return {
        scannerName: this.name,
        status: 'error',
        error: { message: error.message, cause: error },
        durationMs: Date.now() - startedAt,
      };
    }
  }
}
