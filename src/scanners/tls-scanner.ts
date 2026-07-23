import type { AuditContext, Scanner, ScannerResult } from '../core/types/index.js';
import {
  resolveAndValidateAddress,
  defaultResolveHostname,
  type ResolveHostname,
} from '../core/http/http-client.js';
import { NodeTlsProbe, type TlsProbe } from '../core/http/tls-probe.js';

const DEFAULT_TLS_PORT = 443;

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
    return new URL(context.target.normalizedUrl).protocol === 'https:';
  }

  async run(context: AuditContext): Promise<ScannerResult> {
    const startedAt = Date.now();
    const url = new URL(context.target.normalizedUrl);

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
  }
}
