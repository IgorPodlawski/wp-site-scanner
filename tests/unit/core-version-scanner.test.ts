import { describe, expect, it } from 'vitest';
import { CoreVersionScanner } from '@scanners/core-version-scanner.js';
import type { DefaultAuditContext } from '@core/types/audit-context.js';
import { buildTestContext, buildHttpResponse } from '../support/test-context.js';

function createContext(body: string): DefaultAuditContext {
  const context = buildTestContext();
  context.setHttpResponse(buildHttpResponse(body));
  context.setDetectedWordPress(true);
  return context;
}

describe('CoreVersionScanner', () => {
  it('reaches confirmed when generator meta and asset query string agree', async () => {
    const context = createContext(
      '<meta name="generator" content="WordPress 6.5.2" />' +
        '<script src="/wp-includes/js/wp-embed.min.js?ver=6.5.2"></script>',
    );
    const scanner = new CoreVersionScanner();

    const result = await scanner.run(context);

    expect(result.data).toEqual({
      version: {
        value: '6.5.2',
        sources: ['generator-meta', 'asset-query-string'],
        confidence: 'confirmed',
      },
    });
  });

  it('caps a lone generator meta tag at corroborated', async () => {
    const context = createContext('<meta name="generator" content="WordPress 6.5.2" />');
    const scanner = new CoreVersionScanner();

    const result = await scanner.run(context);

    expect(result.data).toEqual({
      version: { value: '6.5.2', sources: ['generator-meta'], confidence: 'corroborated' },
    });
  });

  it('caps a lone asset query string at inferred (cache-busters lie)', async () => {
    const context = createContext(
      '<script src="/wp-includes/js/wp-embed.min.js?ver=6.4.0"></script>',
    );
    const scanner = new CoreVersionScanner();

    const result = await scanner.run(context);

    expect(result.data).toEqual({
      version: { value: '6.4.0', sources: ['asset-query-string'], confidence: 'inferred' },
    });
  });

  it('drops the asset query string when it conflicts with the generator meta tag', async () => {
    const context = createContext(
      '<meta name="generator" content="WordPress 6.5.2" />' +
        '<script src="/wp-includes/js/wp-embed.min.js?ver=6.4.0"></script>',
    );
    const scanner = new CoreVersionScanner();

    const result = await scanner.run(context);

    expect(result.data).toEqual({
      version: { value: '6.5.2', sources: ['generator-meta'], confidence: 'corroborated' },
    });
  });

  it('ignores a bundled third-party library version even when it appears first in the HTML', async () => {
    // Real-world regression: jquery.min.js?ver=3.7.1 is jQuery's own version,
    // unrelated to WordPress core — and 3.7.1 also happens to be a real,
    // ancient, insecure WP release, so mistaking one for the other doesn't
    // just misreport the version, it falsely flags a healthy site as running
    // known-vulnerable core.
    const context = createContext(
      '<script src="/wp-includes/js/jquery/jquery.min.js?ver=3.7.1"></script>' +
        '<script src="/wp-includes/js/jquery/jquery-migrate.min.js?ver=3.4.1"></script>' +
        '<script src="/wp-includes/js/wp-emoji-release.min.js?ver=7.0.2"></script>',
    );
    const scanner = new CoreVersionScanner();

    const result = await scanner.run(context);

    expect(result.data).toEqual({
      version: { value: '7.0.2', sources: ['asset-query-string'], confidence: 'inferred' },
    });
  });

  it('ignores a block-editor "dist" bundle whose ?ver= is a content hash, not a version', async () => {
    // Real-world regression: wp-includes/js/dist/*.min.js sometimes carries a
    // build hash (e.g. "7496969728") as its cache-buster instead of the WP
    // version — this must never be treated as a candidate core version.
    const context = createContext(
      '<script src="/wp-includes/js/dist/hooks.min.js?ver=7496969728"></script>' +
        '<script src="/wp-includes/js/dist/i18n.min.js?ver=781"></script>' +
        '<script src="/wp-includes/js/wp-emoji-release.min.js?ver=7.0.2"></script>',
    );
    const scanner = new CoreVersionScanner();

    const result = await scanner.run(context);

    expect(result.data).toEqual({
      version: { value: '7.0.2', sources: ['asset-query-string'], confidence: 'inferred' },
    });
  });

  it('accepts dashicons.min.css as a reliable core-version-tracking asset', async () => {
    const context = createContext(
      '<link rel="stylesheet" href="/wp-includes/css/dashicons.min.css?ver=7.1" />',
    );
    const scanner = new CoreVersionScanner();

    const result = await scanner.run(context);

    expect(result.data).toEqual({
      version: { value: '7.1', sources: ['asset-query-string'], confidence: 'inferred' },
    });
  });

  it('accepts wp-util.min.js as a reliable core-version-tracking asset', async () => {
    // Real-world regression: a site whose homepage referenced none of the
    // original three allowlisted files (no emoji script, no wp-embed, no
    // dashicons — all plausible if a plugin disables them, or dashicons is
    // only enqueued for logged-in users) still exposed wp-util.min.js, which
    // WordPress core registers with no explicit version (defaults to
    // $wp_version, confirmed against script-loader.php) — same as the
    // original three.
    const context = createContext(
      '<script src="/wp-includes/js/wp-util.min.js?ver=6.5.4"></script>',
    );
    const scanner = new CoreVersionScanner();

    const result = await scanner.run(context);

    expect(result.data).toEqual({
      version: { value: '6.5.4', sources: ['asset-query-string'], confidence: 'inferred' },
    });
  });

  it('accepts block-library/style.min.css as a reliable core-version-tracking asset', async () => {
    const context = createContext(
      '<link rel="stylesheet" href="/wp-includes/css/dist/block-library/style.min.css?ver=6.5.4" />',
    );
    const scanner = new CoreVersionScanner();

    const result = await scanner.run(context);

    expect(result.data).toEqual({
      version: { value: '6.5.4', sources: ['asset-query-string'], confidence: 'inferred' },
    });
  });

  it('ignores a cache-busting timestamp rewritten onto an allowlisted core asset', async () => {
    // Real-world regression: WP Rocket (and similar optimization plugins) rewrite
    // every enqueued script/style's ?ver=, including allowlisted core files, to a
    // sitewide cache-busting value — seen live as a 10-digit Unix timestamp on
    // dashicons.min.css. Being on the allowlist path is necessary but not
    // sufficient; the value itself must still look like a version.
    const context = createContext(
      '<link rel="stylesheet" href="/wp-includes/css/dashicons.min.css?ver=1774442679" />',
    );
    const scanner = new CoreVersionScanner();

    const result = await scanner.run(context);

    expect(result.data).toEqual({ version: undefined });
  });

  it('ignores a content hash rewritten onto wp-emoji-release.min.js', async () => {
    // Real-world regression: wp-emoji-release.min.js?ver=85d537c6 (a hex content
    // hash, not a version) was previously partial-matched by a digits-only
    // pattern as the bogus version "85".
    const context = createContext(
      '<script src="/wp-includes/js/wp-emoji-release.min.js?ver=85d537c6"></script>',
    );
    const scanner = new CoreVersionScanner();

    const result = await scanner.run(context);

    expect(result.data).toEqual({ version: undefined });
  });

  it('returns no version when neither signal is present', async () => {
    const context = createContext('<html><body>Hello</body></html>');
    const scanner = new CoreVersionScanner();

    const result = await scanner.run(context);

    expect(result.data).toEqual({ version: undefined });
  });

  it('supports() is false until WordPress has been detected', () => {
    const freshContext = buildTestContext();
    const scanner = new CoreVersionScanner();

    expect(scanner.supports(freshContext)).toBe(false);
  });
});
