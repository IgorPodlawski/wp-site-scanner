import { randomUUID } from 'node:crypto';
import type {
  Scanner,
  AuthorizationMode,
  ConsentArtifact,
  Target,
  AuditResult,
  AuditStatus,
  AuditContext,
  Finding,
} from '../types/index.js';
import type { AuditRequest } from './audit-request.js';
import type { AppConfig } from '../../config/types.js';
import type { Logger } from '../../utils/logger.js';
import { buildTarget } from '../types/target.js';
import { DefaultAuditContext } from '../types/audit-context.js';
import { createFinding } from '../types/finding.js';
import { AuditFailureError, MissingConsentError } from '../errors.js';
import { saveAuditResult } from '../../storage/json-store.js';
import {
  generateFindings,
  WORDPRESS_ORG_PLUGIN_ENRICHMENT,
} from '../../analysis/finding-engine.js';
import type { WordPressOrgClient } from '../../integrations/wordpress-org-client.js';
import type { WordPressOrgPluginInfo } from '../../integrations/enrichment-types.js';
import type { DetectedPlugin } from '../../scanners/plugin-scanner.js';

const AUTH_RANK: Record<AuthorizationMode, number> = { prospect: 0, audit: 1 };

/**
 * Filters scanners by the active authorization mode. This is the mechanical
 * enforcement of "the orchestrator filters scanners by minAuthorization
 * before running them" — a scanner requiring 'audit' must never run under
 * 'prospect', even if constructed and called by mistake elsewhere.
 */
export function filterScannersByAuthorization(
  scanners: readonly Scanner[],
  mode: AuthorizationMode,
): Scanner[] {
  const modeRank = AUTH_RANK[mode];
  return scanners.filter((scanner) => AUTH_RANK[scanner.minAuthorization] <= modeRank);
}

export interface ResolvedAuthorization {
  mode: AuthorizationMode;
  consentArtifact?: ConsentArtifact;
}

/**
 * Resolves the requested mode against the consent gate. Fails fast — never
 * silently downgrades audit to prospect when consent is missing.
 */
export function resolveAuthorizationMode(
  request: AuditRequest,
  target: Target,
): ResolvedAuthorization {
  if (request.requestedMode === 'prospect') {
    return { mode: 'prospect' };
  }

  if (!request.consent?.confirmed) {
    throw new MissingConsentError(target.domain);
  }

  const consentArtifact: ConsentArtifact = {
    targetDomain: target.domain,
    confirmed: true,
    timestamp: new Date().toISOString(),
    ...(request.consent.operatorNote !== undefined
      ? { operatorNote: request.consent.operatorNote }
      : {}),
    source: request.consent.source,
  };

  return { mode: 'audit', consentArtifact };
}

/**
 * Coordinates the audit. Does NOT perform technical analysis — that is the
 * scanners' and finding engine's job. Runs scanners in registration order
 * (see scanner-registry.ts, which lists them in pipeline order),
 * short-circuiting after wordpress-detector if the target isn't WordPress.
 * Scoring, sales insights, external enrichment and HTML/PDF reports are
 * later phases (see CLAUDE.md "Roadmap") — this wires scanners and the
 * finding engine through to a persisted JSON AuditResult.
 */
export class AuditOrchestrator {
  constructor(
    private readonly scanners: readonly Scanner[],
    private readonly config: AppConfig,
    private readonly logger: Logger,
    private readonly wordPressOrgClient: WordPressOrgClient,
  ) {}

  filterScanners(mode: AuthorizationMode): Scanner[] {
    return filterScannersByAuthorization(this.scanners, mode);
  }

  async run(request: AuditRequest): Promise<AuditResult> {
    const target = buildTarget(request.targetInput);

    // Fails fast on missing consent; never silently downgrades audit to prospect.
    const { mode, consentArtifact } = resolveAuthorizationMode(request, target);
    const scanners = this.filterScanners(mode);

    const context = new DefaultAuditContext({
      target,
      authorizationMode: mode,
      profile: request.profile,
      ...(consentArtifact ? { consentArtifact } : {}),
      startedAt: new Date().toISOString(),
    });

    const limitations = await this.runScanners(scanners, context);

    const isWordPress = context.isWordPress() ?? false;
    if (isWordPress) {
      const enrichmentLimitation = await this.enrichPlugins(context);
      if (enrichmentLimitation) limitations.push(enrichmentLimitation);
    }

    const findings: Finding[] = isWordPress
      ? generateFindings(context)
      : [this.buildNotWordPressFinding(target)];
    const status: AuditStatus = limitations.length > 0 ? 'partial' : 'completed';

    const result: AuditResult = {
      id: randomUUID(),
      target,
      authorizationMode: mode,
      profile: request.profile,
      ...(consentArtifact ? { consentArtifact } : {}),
      status,
      startedAt: context.startedAt,
      finishedAt: new Date().toISOString(),
      isWordPress,
      scannerResults: context.getScannerResults(),
      findings,
      limitations,
    };

    await saveAuditResult(result);
    return result;
  }

  /**
   * Runs each supported scanner in order, short-circuiting once
   * wordpress-detector reports a non-WordPress target — the tool's whole
   * purpose is WordPress-specific, so nothing further applies. A scanner
   * throwing an AuditFailureError (SSRF rejection, unreachable host, ...) is
   * a target-level problem and propagates to fail the whole run; any other
   * scanner error is recorded as a limitation and the run continues.
   */
  private async runScanners(
    scanners: readonly Scanner[],
    context: AuditContext,
  ): Promise<string[]> {
    const limitations: string[] = [];

    for (const scanner of scanners) {
      if (!scanner.supports(context)) continue;

      this.logger.info({ scanner: scanner.name }, 'Running scanner');
      try {
        const result = await scanner.run(context);
        context.addScannerResult(result);
        if (result.status === 'error') {
          limitations.push(`${scanner.name}: ${result.error?.message ?? 'reported an error'}`);
        }
      } catch (error) {
        if (error instanceof AuditFailureError) {
          throw error;
        }
        const message = error instanceof Error ? error.message : String(error);
        context.addScannerResult({
          scannerName: scanner.name,
          status: 'error',
          error: { message },
          durationMs: 0,
        });
        limitations.push(`${scanner.name} failed: ${message}`);
        this.logger.warn({ scanner: scanner.name, error: message }, 'Scanner failed');
      }

      if (scanner.name === 'wordpress-detector' && context.isWordPress() === false) {
        this.logger.info('Target is not WordPress — finalizing without further scanners.');
        break;
      }
    }

    return limitations;
  }

  /**
   * WordPress.org lookups are prospect-safe third-party enrichment (per
   * CLAUDE.md's "what each mode may touch"), so this runs regardless of
   * authorization mode whenever plugins were detected. A lookup failure
   * (network/API trouble) degrades the run to 'partial'; a plugin simply
   * not being on wordpress.org (closed/premium/custom) is a normal outcome
   * and is not a limitation.
   */
  private async enrichPlugins(context: AuditContext): Promise<string | undefined> {
    const pluginResult = context
      .getScannerResults()
      .find((r) => r.scannerName === 'plugin-scanner' && r.status === 'ok');
    const plugins = (pluginResult?.data as { plugins: DetectedPlugin[] } | undefined)?.plugins;
    if (!plugins || plugins.length === 0) return undefined;

    const lookups = await Promise.all(
      plugins.map(async (plugin) => ({
        slug: plugin.slug,
        result: await this.wordPressOrgClient.getPluginInfo(plugin.slug),
      })),
    );

    const enrichment: Record<string, WordPressOrgPluginInfo | undefined> = {};
    let failureCount = 0;
    for (const { slug, result } of lookups) {
      if (result.ok) {
        enrichment[slug] = result.value;
      } else {
        failureCount += 1;
        this.logger.warn(
          { slug, error: result.error.message },
          'WordPress.org plugin lookup failed',
        );
      }
    }

    context.setEnrichment(WORDPRESS_ORG_PLUGIN_ENRICHMENT, enrichment);
    return failureCount > 0
      ? `wordpress-org plugin lookup failed for ${failureCount} of ${plugins.length} plugin(s)`
      : undefined;
  }

  private buildNotWordPressFinding(target: Target): Finding {
    return createFinding({
      id: randomUUID(),
      category: 'infrastructure',
      confidence: 'confirmed',
      requestedSeverity: 'info',
      sourceLayer: 1,
      businessImpact: 'none',
      recommendationKey: 'finding.notWordpress.recommendation',
      evidence: [
        {
          descriptionKey: 'finding.notWordpress.evidence',
          params: { domain: target.domain },
        },
      ],
    });
  }
}
