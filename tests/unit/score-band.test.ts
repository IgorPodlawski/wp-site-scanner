import { describe, expect, it } from 'vitest';
import { getScoreBand } from '@analysis/score-band.js';

describe('getScoreBand', () => {
  it('classifies below 50 as poor', () => {
    expect(getScoreBand(0)).toBe('poor');
    expect(getScoreBand(49)).toBe('poor');
  });

  it('classifies 50-89 as fair', () => {
    expect(getScoreBand(50)).toBe('fair');
    expect(getScoreBand(89)).toBe('fair');
  });

  it('classifies 90 and above as good', () => {
    expect(getScoreBand(90)).toBe('good');
    expect(getScoreBand(100)).toBe('good');
  });
});
