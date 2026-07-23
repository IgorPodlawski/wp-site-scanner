import type { AuditContext, Scanner, ScannerResult } from '../core/types/index.js';
import type { HttpResponse } from '../core/http/http-client.js';
import type { VersionInfo, VersionSource } from '../core/types/version.js';
import { deriveConfidence } from '../analysis/version-confidence.js';

const GENERATOR_PATTERN = /<meta[^>]+name=["']generator["'][^>]*wordpress\s+([\d.]+)/i;
const ASSET_QUERY_PATTERN = /\/wp-(?:includes|admin)\/[^"'\s]+\?ver=([\d.]+)/i;

/** Detects WordPress core version from generator meta / asset query strings. */
export class CoreVersionScanner implements Scanner {
  readonly name = 'core-version-scanner';
  readonly minAuthorization = 'prospect' as const;

  supports(context: AuditContext): boolean {
    return context.isWordPress() === true;
  }

  async run(context: AuditContext): Promise<ScannerResult> {
    const startedAt = Date.now();
    const response = context.getHttpResponse() as HttpResponse;

    const generatorVersion = response.body.match(GENERATOR_PATTERN)?.[1];
    const assetQueryVersion = response.body.match(ASSET_QUERY_PATTERN)?.[1];

    const version = this.buildVersionInfo(generatorVersion, assetQueryVersion);

    return {
      scannerName: this.name,
      status: 'ok',
      data: { version },
      durationMs: Date.now() - startedAt,
    };
  }

  private buildVersionInfo(
    generatorVersion: string | undefined,
    assetQueryVersion: string | undefined,
  ): VersionInfo | undefined {
    // Independent sources agreeing is what earns 'confirmed'; a conflict between
    // them means the query-string source is unreliable here, so it's dropped
    // rather than trusted (false positives are worse than misses).
    if (generatorVersion && assetQueryVersion && generatorVersion === assetQueryVersion) {
      return this.toVersionInfo(generatorVersion, ['generator-meta', 'asset-query-string']);
    }
    if (generatorVersion) {
      return this.toVersionInfo(generatorVersion, ['generator-meta']);
    }
    if (assetQueryVersion) {
      return this.toVersionInfo(assetQueryVersion, ['asset-query-string']);
    }
    return undefined;
  }

  private toVersionInfo(value: string, sources: VersionSource[]): VersionInfo {
    return { value, sources, confidence: deriveConfidence(sources) };
  }
}
