import { describe, expect, it } from 'vitest';
import {
  compareVersions,
  deriveConfidence,
  deriveVersionInfo,
} from '@analysis/version-confidence.js';

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

describe('compareVersions', () => {
  it('detects an older version regardless of segment count', () => {
    expect(compareVersions('5.3', '5.3.3')).toBe(-1);
    expect(compareVersions('5.2.9', '5.3.0')).toBe(-1);
  });

  it('detects a newer version', () => {
    expect(compareVersions('6.0.0', '5.9.9')).toBe(1);
  });

  it('treats equal versions as equal', () => {
    expect(compareVersions('5.3.3', '5.3.3')).toBe(0);
    expect(compareVersions('5.3', '5.3.0')).toBe(0);
  });

  it('abstains (undefined) when either version has a non-numeric segment', () => {
    expect(compareVersions('5.3-beta', '5.3.3')).toBeUndefined();
    expect(compareVersions('5.3.3', '5.x')).toBeUndefined();
  });
});
