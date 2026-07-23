import net from 'node:net';
import dns from 'node:dns/promises';
import { Agent, buildConnector, request as undiciRequest, type Dispatcher } from 'undici';
import { isSafeToFetch, isSafeIpAddress } from './ssrf-guard.js';
import { SsrfRejectedError, UnreachableTargetError } from '../errors.js';

export interface HttpResponse {
  url: string;
  status: number;
  headers: Record<string, string>;
  body: string;
}

export interface HttpClientOptions {
  timeoutMs: number;
  maxRedirects: number;
  maxResponseBytes: number;
  userAgent: string;
}

export interface HttpClient {
  /**
   * Fetches a URL through undici with the SSRF guard re-applied to the
   * resolved address on the initial request and on every redirect hop, plus
   * timeout and response-size enforcement.
   */
  fetchUrl(url: string, options: HttpClientOptions): Promise<HttpResponse>;
}

type ResolveHostname = (hostname: string) => Promise<string[]>;
type CreateDispatcher = (resolvedIp: string) => Dispatcher;

async function defaultResolveHostname(hostname: string): Promise<string[]> {
  const results = await dns.lookup(hostname, { all: true, verbatim: true });
  return results.map((result) => result.address);
}

/**
 * Builds a per-request Agent pinned to `resolvedIp`: the socket connects to
 * the address we already validated, while SNI/Host still use the original
 * hostname. This closes the TOCTOU gap where DNS could resolve to a
 * different (private) address between our check and the actual connection.
 */
function createPinnedDispatcher(resolvedIp: string): Dispatcher {
  const connect = buildConnector({});
  return new Agent({
    connect: (options, callback) => {
      connect({ ...options, hostname: resolvedIp, servername: options.hostname }, callback);
    },
  });
}

function isRedirect(status: number): boolean {
  return status >= 300 && status < 400;
}

function firstHeaderValue(value: string | string[] | undefined): string | undefined {
  return Array.isArray(value) ? value[0] : value;
}

function normalizeHeaders(
  headers: Record<string, string | string[] | undefined>,
): Record<string, string> {
  const normalized: Record<string, string> = {};
  for (const [key, value] of Object.entries(headers)) {
    if (value === undefined) continue;
    normalized[key] = Array.isArray(value) ? value.join(', ') : value;
  }
  return normalized;
}

async function readBodyWithLimit(
  body: Dispatcher.ResponseData['body'],
  maxBytes: number,
  url: string,
): Promise<string> {
  const chunks: Buffer[] = [];
  let total = 0;
  for await (const chunk of body) {
    const buffer = chunk as Buffer;
    total += buffer.length;
    if (total > maxBytes) {
      body.destroy();
      throw new UnreachableTargetError(
        url,
        new Error(`Response exceeded the ${maxBytes}-byte limit.`),
      );
    }
    chunks.push(buffer);
  }
  return Buffer.concat(chunks).toString('utf-8');
}

export class UndiciHttpClient implements HttpClient {
  constructor(
    private readonly resolveHostname: ResolveHostname = defaultResolveHostname,
    private readonly createDispatcher: CreateDispatcher = createPinnedDispatcher,
  ) {}

  async fetchUrl(url: string, options: HttpClientOptions): Promise<HttpResponse> {
    let currentUrl = new URL(url);
    let redirectCount = 0;

    for (;;) {
      const resolvedIp = await this.resolveAndValidate(currentUrl);
      const dispatcher = this.createDispatcher(resolvedIp);
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), options.timeoutMs);

      try {
        let response: Dispatcher.ResponseData;
        try {
          response = await undiciRequest(currentUrl, {
            dispatcher,
            method: 'GET',
            headers: { 'user-agent': options.userAgent },
            signal: controller.signal,
          });
        } catch (cause) {
          throw new UnreachableTargetError(currentUrl.toString(), cause);
        }

        if (isRedirect(response.statusCode)) {
          response.body.destroy();
          const location = firstHeaderValue(response.headers['location']);
          if (!location) {
            throw new UnreachableTargetError(
              currentUrl.toString(),
              new Error(`Redirect response (${response.statusCode}) missing a Location header.`),
            );
          }

          redirectCount += 1;
          if (redirectCount > options.maxRedirects) {
            throw new UnreachableTargetError(
              currentUrl.toString(),
              new Error(`Exceeded the maximum of ${options.maxRedirects} redirects.`),
            );
          }

          currentUrl = new URL(location, currentUrl);
          continue;
        }

        const body = await readBodyWithLimit(
          response.body,
          options.maxResponseBytes,
          currentUrl.toString(),
        );
        return {
          url: currentUrl.toString(),
          status: response.statusCode,
          headers: normalizeHeaders(response.headers),
          body,
        };
      } finally {
        clearTimeout(timer);
        await dispatcher.close();
      }
    }
  }

  private async resolveAndValidate(url: URL): Promise<string> {
    const schemeAndHostCheck = isSafeToFetch(url);
    if (!schemeAndHostCheck.safe) {
      throw new SsrfRejectedError(
        url.toString(),
        schemeAndHostCheck.reason ?? 'blocked by SSRF guard',
      );
    }

    const hostname = url.hostname.replace(/^\[|\]$/g, '');
    if (net.isIP(hostname)) {
      // Literal IP in the URL — already validated above, nothing to resolve.
      return hostname;
    }

    let addresses: string[];
    try {
      addresses = await this.resolveHostname(hostname);
    } catch (cause) {
      throw new UnreachableTargetError(url.toString(), cause);
    }

    const resolvedIp = addresses[0];
    if (!resolvedIp) {
      throw new UnreachableTargetError(
        url.toString(),
        new Error('DNS resolution returned no addresses.'),
      );
    }

    const resolvedCheck = isSafeIpAddress(resolvedIp);
    if (!resolvedCheck.safe) {
      throw new SsrfRejectedError(
        url.toString(),
        `Hostname resolved to a blocked address: ${resolvedCheck.reason ?? resolvedIp}`,
      );
    }

    return resolvedIp;
  }
}
