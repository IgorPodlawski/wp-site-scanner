import type { AuditContext, Scanner, ScannerResult } from '../core/types/index.js';
import type { HttpClient, HttpClientOptions } from '../core/http/http-client.js';
import { UndiciHttpClient } from '../core/http/http-client.js';

/** Fetches the homepage (+ assets already referenced by the HTML). Foundation for all other scanners. */
export class HttpScanner implements Scanner {
  readonly name = 'http-scanner';
  readonly minAuthorization = 'prospect' as const;

  constructor(
    private readonly options: HttpClientOptions,
    private readonly httpClient: HttpClient = new UndiciHttpClient(),
  ) {}

  supports(_context: AuditContext): boolean {
    return true;
  }

  async run(context: AuditContext): Promise<ScannerResult> {
    const startedAt = Date.now();
    const response = await this.httpClient.fetchUrl(context.target.normalizedUrl, this.options);
    context.setHttpResponse(response);

    return {
      scannerName: this.name,
      status: 'ok',
      data: { status: response.status, url: response.url },
      durationMs: Date.now() - startedAt,
    };
  }
}
