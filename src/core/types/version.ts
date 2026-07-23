export type VersionSource =
  | 'generator-meta'
  | 'asset-query-string'
  | 'plugin-readme'
  | 'theme-stylesheet'
  | 'wp-json-api'
  | 'http-header';

export type VersionConfidence = 'inferred' | 'corroborated' | 'confirmed';

export interface VersionInfo {
  value: string;
  sources: VersionSource[];
  confidence: VersionConfidence;
}
