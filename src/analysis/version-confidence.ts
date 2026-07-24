import type { VersionConfidence, VersionInfo, VersionSource } from '../core/types/version.js';

/**
 * A real WordPress version (core, plugin, or theme) is always at least
 * major.minor ("6.4", "5.9.3") — requiring the dot rejects the two garbage
 * shapes seen live: a bare cache-busting timestamp (no dot at all, e.g.
 * `?ver=1774442679`) and a content hash (`?ver=85d537c6`, which a
 * digits-only pattern used to partial-match as the bogus version `"85"`).
 * Shared so every version-extracting scanner enforces the same shape.
 */
export const WP_VERSION_SHAPE = String.raw`\d+\.\d+(?:\.\d+)?`;

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

export interface VersionCandidate {
  value: string;
  source: VersionSource;
}

/**
 * Merges same-valued candidates into one VersionInfo. Candidates that
 * disagree never get merged into a false 'confirmed' — the largest
 * agreeing group wins, and ties break toward whichever candidate was listed
 * first (callers list their most-trusted source first).
 */
export function deriveVersionInfo(
  candidates: ReadonlyArray<VersionCandidate | undefined>,
): VersionInfo | undefined {
  const present = candidates.filter((candidate): candidate is VersionCandidate => !!candidate);
  if (present.length === 0) {
    return undefined;
  }

  const groups = new Map<string, VersionSource[]>();
  for (const { value, source } of present) {
    const sources = groups.get(value);
    if (sources) {
      sources.push(source);
    } else {
      groups.set(value, [source]);
    }
  }

  const maxSize = Math.max(...[...groups.values()].map((sources) => sources.length));
  const [value, sources] = [...groups.entries()].find(([, s]) => s.length === maxSize)!;

  return { value, sources, confidence: deriveConfidence(sources) };
}

/**
 * Compares two dotted-numeric version strings: -1 if `a` < `b`, 0 if equal,
 * 1 if `a` > `b`. Returns `undefined` when either string has a non-numeric
 * segment (e.g. a cache-busting timestamp or a "1.0-beta" suffix) — abstain
 * rather than risk a false "outdated" finding on data that isn't really a
 * comparable version.
 */
export function compareVersions(a: string, b: string): number | undefined {
  const partsA = a.split('.').map(Number);
  const partsB = b.split('.').map(Number);
  if (partsA.some(Number.isNaN) || partsB.some(Number.isNaN)) {
    return undefined;
  }

  const length = Math.max(partsA.length, partsB.length);
  for (let i = 0; i < length; i += 1) {
    const diff = (partsA[i] ?? 0) - (partsB[i] ?? 0);
    if (diff !== 0) {
      return diff > 0 ? 1 : -1;
    }
  }
  return 0;
}
