import { describe, expect, it } from 'vitest';
import { severityFromCvss } from '@analysis/cvss-severity.js';

describe('severityFromCvss', () => {
  it('maps 9.0-10.0 to critical', () => {
    expect(severityFromCvss(9.0)).toBe('critical');
    expect(severityFromCvss(9.8)).toBe('critical');
    expect(severityFromCvss(10.0)).toBe('critical');
  });

  it('maps 7.0-8.9 to high', () => {
    expect(severityFromCvss(7.0)).toBe('high');
    expect(severityFromCvss(8.9)).toBe('high');
  });

  it('maps 4.0-6.9 to medium', () => {
    expect(severityFromCvss(4.0)).toBe('medium');
    expect(severityFromCvss(6.9)).toBe('medium');
  });

  it('maps 0.1-3.9 to low', () => {
    expect(severityFromCvss(0.1)).toBe('low');
    expect(severityFromCvss(3.9)).toBe('low');
  });

  it('maps 0 to info', () => {
    expect(severityFromCvss(0)).toBe('info');
  });

  it('handles the exact boundary between every adjacent pair correctly', () => {
    expect(severityFromCvss(8.9)).toBe('high');
    expect(severityFromCvss(9.0)).toBe('critical');
    expect(severityFromCvss(6.9)).toBe('medium');
    expect(severityFromCvss(7.0)).toBe('high');
    expect(severityFromCvss(3.9)).toBe('low');
    expect(severityFromCvss(4.0)).toBe('medium');
    expect(severityFromCvss(0)).toBe('info');
    expect(severityFromCvss(0.1)).toBe('low');
  });
});
