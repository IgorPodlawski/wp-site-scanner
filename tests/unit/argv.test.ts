import { describe, expect, it } from 'vitest';
import { stripLeadingPassthroughSeparator } from '@/cli/argv.js';

describe('stripLeadingPassthroughSeparator', () => {
  it('drops a leading "--" (as forwarded by `pnpm <script> -- <args>`)', () => {
    const argv = ['node', 'index.ts', '--', 'audit', 'https://example.com', '--profile', 'deep'];

    expect(stripLeadingPassthroughSeparator(argv)).toEqual([
      'node',
      'index.ts',
      'audit',
      'https://example.com',
      '--profile',
      'deep',
    ]);
  });

  it('leaves argv untouched when there is no leading "--"', () => {
    const argv = ['node', 'index.ts', 'audit', 'https://example.com', '--profile', 'deep'];

    expect(stripLeadingPassthroughSeparator(argv)).toEqual(argv);
  });

  it('does not touch a "--" that appears later in the arguments', () => {
    const argv = ['node', 'index.ts', 'audit', 'https://example.com', '--', 'literal-arg'];

    expect(stripLeadingPassthroughSeparator(argv)).toEqual(argv);
  });

  it('handles a bare argv with nothing past the leading "--"', () => {
    expect(stripLeadingPassthroughSeparator(['node', 'index.ts', '--'])).toEqual([
      'node',
      'index.ts',
    ]);
  });
});
