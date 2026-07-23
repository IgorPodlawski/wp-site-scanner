/** Real, tiny helper — implements the exact `provider:type:identifier:version` cache-key format. */
export function buildCacheKey(
  provider: string,
  type: string,
  identifier: string,
  version: string,
): string {
  return `${provider}:${type}:${identifier}:${version}`;
}
