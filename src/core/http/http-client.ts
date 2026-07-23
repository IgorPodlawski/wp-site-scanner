import { NotImplementedError } from '../errors.js';

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

// TODO (Phase 1 feature work): implement against undici — resolve DNS, run
// isSafeToFetch() against the resolved address, enforce timeoutMs via
// AbortController, follow redirects up to maxRedirects re-validating SSRF on
// each hop, and cap response size at maxResponseBytes.
export class UndiciHttpClient implements HttpClient {
  fetchUrl(_url: string, _options: HttpClientOptions): Promise<HttpResponse> {
    throw new NotImplementedError('HttpClient.fetchUrl (Phase 1 feature work)');
  }
}
