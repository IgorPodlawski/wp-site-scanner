import { describe, expect, it } from 'vitest';
import { deriveConfidence } from '@analysis/version-confidence.js';

describe('deriveConfidence', () => {
  it('caps a lone asset-query-string source at inferred (cache-busters lie)', () => {
    expect(deriveConfidence(['asset-query-string'])).toBe('inferred');
  });

  it('caps any other single source at corroborated', () => {
    expect(deriveConfidence(['plugin-readme'])).toBe('corroborated');
    expect(deriveConfidence(['generator-meta'])).toBe('corroborated');
  });

  it('reaches confirmed when two independent sources agree', () => {
    expect(deriveConfidence(['plugin-readme', 'theme-stylesheet'])).toBe('confirmed');
  });

  it('returns inferred when there are no sources', () => {
    expect(deriveConfidence([])).toBe('inferred');
  });
});
