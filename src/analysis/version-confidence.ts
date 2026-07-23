import type { VersionConfidence, VersionSource } from '../core/types/version.js';

/**
 * Real, pure implementation of the version-confidence rules from CLAUDE.md:
 * `?ver=` on an asset is inferred at best (cache-busters lie); any other
 * single source reaches at most 'corroborated'; 'confirmed' requires two
 * independent sources agreeing.
 */
export function deriveConfidence(sources: readonly VersionSource[]): VersionConfidence {
  const distinctSources = new Set(sources);

  if (distinctSources.size === 0) {
    return 'inferred';
  }
  if (distinctSources.size === 1) {
    const [only] = distinctSources;
    return only === 'asset-query-string' ? 'inferred' : 'corroborated';
  }
  return 'confirmed';
}
