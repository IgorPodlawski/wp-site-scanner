import { describe, expect, it } from 'vitest';
import { deriveConfidence, deriveVersionInfo } from '@analysis/version-confidence.js';

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

describe('deriveVersionInfo', () => {
  it('returns undefined when no candidate is present', () => {
    expect(deriveVersionInfo([undefined, undefined])).toBeUndefined();
  });

  it('merges agreeing candidates into a confirmed VersionInfo', () => {
    const result = deriveVersionInfo([
      { value: '6.5.2', source: 'plugin-readme' },
      { value: '6.5.2', source: 'asset-query-string' },
    ]);

    expect(result).toEqual({
      value: '6.5.2',
      sources: ['plugin-readme', 'asset-query-string'],
      confidence: 'confirmed',
    });
  });

  it('breaks a conflict toward the first-listed (most trusted) candidate', () => {
    const result = deriveVersionInfo([
      { value: '6.5.2', source: 'plugin-readme' },
      { value: '6.4.0', source: 'asset-query-string' },
    ]);

    expect(result).toEqual({
      value: '6.5.2',
      sources: ['plugin-readme'],
      confidence: 'corroborated',
    });
  });

  it('caps a lone asset-query-string candidate at inferred', () => {
    const result = deriveVersionInfo([{ value: '6.4.0', source: 'asset-query-string' }]);

    expect(result).toEqual({
      value: '6.4.0',
      sources: ['asset-query-string'],
      confidence: 'inferred',
    });
  });
});
