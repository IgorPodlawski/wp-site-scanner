import type { HttpClient, HttpClientOptions } from './http-client.js';
import { mapWithConcurrency } from '../../utils/concurrency.js';

const ASSET_URL_PATTERN = /(?:href|src)=["']([^"'?#]+\.(?:css|js))(?:[?#][^"']*)?["']/gi;

/** Caps how many referenced assets a single --profile deep scan will fetch — politeness, not a hard technical limit. */
const MAX_ASSETS = 30;
const ASSET_FETCH_CONCURRENCY = 5;

/**
 * Extracts CSS/JS asset URLs referenced from an HTML document (`<link
 * href>`, `<script src>`), resolved against `baseUrl`. This is exactly
 * "assets already referenced by the HTML" per CLAUDE.md's prospect-mode
 * boundary — never a guessed path, only what's already linked from the page
 * we already fetched.
 */
export function extractAssetUrls(html: string, baseUrl: string): string[] {
  const urls = new Set<string>();
  for (const match of html.matchAll(ASSET_URL_PATTERN)) {
    try {
      urls.add(new URL(match[1]!, baseUrl).toString());
    } catch {
      // ignore malformed/unresolvable URLs rather than fail the whole scan
    }
  }
  return [...urls].slice(0, MAX_ASSETS);
}

/** Fetches each asset URL, tolerating individual failures (that URL contributes '' rather than aborting the batch). */
export async function fetchAssetBodies(
  httpClient: HttpClient,
  options: HttpClientOptions,
  urls: readonly string[],
): Promise<string[]> {
  const bodies = await mapWithConcurrency(urls, ASSET_FETCH_CONCURRENCY, async (url) => {
    try {
      const response = await httpClient.fetchUrl(url, options);
      return response.status === 200 ? response.body : '';
    } catch {
      return '';
    }
  });
  return bodies.filter((body) => body.length > 0);
}
