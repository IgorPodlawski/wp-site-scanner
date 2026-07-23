import { InvalidTargetError } from '../errors.js';

export interface Target {
  originalInput: string;
  normalizedUrl: string;
  domain: string;
}

/**
 * Pure parsing/normalization of a target input into a Target value object —
 * no I/O (DNS resolution, SSRF checks, and the actual homepage fetch happen
 * later in the pipeline). Defaults to https:// when no scheme is given, and
 * only accepts http/https.
 */
export function buildTarget(input: string): Target {
  const withScheme = /^https?:\/\//i.test(input) ? input : `https://${input}`;

  let url: URL;
  try {
    url = new URL(withScheme);
  } catch {
    throw new InvalidTargetError(input, 'not a valid URL');
  }

  if (url.protocol !== 'http:' && url.protocol !== 'https:') {
    throw new InvalidTargetError(input, `unsupported protocol "${url.protocol}"`);
  }
  if (!url.hostname) {
    throw new InvalidTargetError(input, 'missing hostname');
  }

  return {
    originalInput: input,
    normalizedUrl: url.toString(),
    domain: url.hostname,
  };
}
