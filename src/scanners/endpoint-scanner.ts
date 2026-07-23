import type { AuditContext, Scanner, ScannerResult } from '../core/types/index.js';
import type { HttpClient, HttpClientOptions, HttpResponse } from '../core/http/http-client.js';

const CONFIG_BACKUP_PATHS = [
  '/wp-config.php.bak',
  '/wp-config.php~',
  '/wp-config.php.save',
  '/wp-config.old',
];

interface EndpointProbeResult {
  exists: boolean;
  error?: string;
}

export interface EndpointScannerData {
  readme: EndpointProbeResult;
  restApiUsers: { exists: boolean; usernames?: string[]; error?: string };
  xmlrpc: { enabled: boolean; error?: string };
  directoryListing: { listingDetected: boolean; error?: string };
  configBackups: Array<{ path: string; exists: boolean; error?: string }>;
}

/**
 * Fetches `path` and reports whether it exists, without letting one probe's
 * network failure (timeout, DNS, etc.) take down the whole scanner — each
 * probe is independent, so a failure is recorded and the others still run.
 */
async function probeExists(
  httpClient: HttpClient,
  options: HttpClientOptions,
  url: string,
): Promise<EndpointProbeResult> {
  try {
    const response = await httpClient.fetchUrl(url, options);
    return { exists: response.status === 200 };
  } catch (cause) {
    return { exists: false, error: cause instanceof Error ? cause.message : String(cause) };
  }
}

/** Audit-only Layer-2 probes: /wp-json/wp/v2/users, xmlrpc.php, /readme.html, directory listing, config backups. */
export class EndpointScanner implements Scanner {
  readonly name = 'endpoint-scanner';
  readonly minAuthorization = 'audit' as const;

  constructor(
    private readonly httpClientOptions: HttpClientOptions,
    private readonly httpClient: HttpClient,
  ) {}

  supports(context: AuditContext): boolean {
    return context.isWordPress() === true;
  }

  async run(context: AuditContext): Promise<ScannerResult> {
    const startedAt = Date.now();
    const response = context.getHttpResponse() as HttpResponse;
    const origin = response.url;

    const [readme, restApiUsers, xmlrpc, directoryListing, configBackups] = await Promise.all([
      this.probeReadme(origin),
      this.probeRestApiUsers(origin),
      this.probeXmlrpc(origin),
      this.probeDirectoryListing(origin),
      Promise.all(CONFIG_BACKUP_PATHS.map((path) => this.probeConfigBackup(origin, path))),
    ]);

    const data: EndpointScannerData = {
      readme,
      restApiUsers,
      xmlrpc,
      directoryListing,
      configBackups,
    };

    return {
      scannerName: this.name,
      status: 'ok',
      data,
      durationMs: Date.now() - startedAt,
    };
  }

  private resolveUrl(origin: string, path: string): string {
    return new URL(path, origin).toString();
  }

  private async probeReadme(origin: string): Promise<EndpointProbeResult> {
    return probeExists(
      this.httpClient,
      this.httpClientOptions,
      this.resolveUrl(origin, '/readme.html'),
    );
  }

  private async probeXmlrpc(origin: string): Promise<{ enabled: boolean; error?: string }> {
    try {
      const response = await this.httpClient.fetchUrl(
        this.resolveUrl(origin, '/xmlrpc.php'),
        this.httpClientOptions,
      );
      return {
        enabled:
          response.status === 200 &&
          /XML-RPC server accepts POST requests only/i.test(response.body),
      };
    } catch (cause) {
      return { enabled: false, error: cause instanceof Error ? cause.message : String(cause) };
    }
  }

  private async probeDirectoryListing(
    origin: string,
  ): Promise<{ listingDetected: boolean; error?: string }> {
    try {
      const response = await this.httpClient.fetchUrl(
        this.resolveUrl(origin, '/wp-content/uploads/'),
        this.httpClientOptions,
      );
      return {
        listingDetected: response.status === 200 && /Index of \//i.test(response.body),
      };
    } catch (cause) {
      return {
        listingDetected: false,
        error: cause instanceof Error ? cause.message : String(cause),
      };
    }
  }

  private async probeRestApiUsers(
    origin: string,
  ): Promise<{ exists: boolean; usernames?: string[]; error?: string }> {
    try {
      const response = await this.httpClient.fetchUrl(
        this.resolveUrl(origin, '/wp-json/wp/v2/users'),
        this.httpClientOptions,
      );
      if (response.status !== 200) {
        return { exists: false };
      }
      const users = JSON.parse(response.body);
      if (!Array.isArray(users)) {
        return { exists: false };
      }
      const usernames = users
        .map((user: unknown) =>
          typeof user === 'object' && user !== null && 'slug' in user
            ? String((user as { slug: unknown }).slug)
            : undefined,
        )
        .filter((slug): slug is string => slug !== undefined);
      return { exists: true, usernames };
    } catch (cause) {
      return { exists: false, error: cause instanceof Error ? cause.message : String(cause) };
    }
  }

  private async probeConfigBackup(
    origin: string,
    path: string,
  ): Promise<{ path: string; exists: boolean; error?: string }> {
    const result = await probeExists(
      this.httpClient,
      this.httpClientOptions,
      this.resolveUrl(origin, path),
    );
    return { path, ...result };
  }
}
