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
  VersionInfo,
} from '../types/index.js';
import type { AuditRequest } from './audit-request.js';
import type { AppConfig } from '../../config/types.js';
import type { Logger } from '../../utils/logger.js';
import { buildTarget } from '../types/target.js';
import type { HttpResponse } from '../http/http-client.js';
import { DefaultAuditContext } from '../types/audit-context.js';
import { getScannerData } from '../types/scanner.js';
import { createFinding } from '../types/finding.js';
import { AuditFailureError, MissingConsentError } from '../errors.js';
import { saveAuditResult } from '../../storage/json-store.js';
import {
  generateFindings,
  calculateReportCounters,
  WORDPRESS_ORG_PLUGIN_ENRICHMENT,
  WORDPRESS_ORG_THEME_ENRICHMENT,
  WORDPRESS_ORG_CORE_ENRICHMENT,
  WPSCAN_PLUGIN_ENRICHMENT,
  WPSCAN_THEME_ENRICHMENT,
  WPSCAN_CORE_ENRICHMENT,
  PAGESPEED_ENRICHMENT,
} from '../../analysis/finding-engine.js';
import { calculateScores } from '../../analysis/scoring-engine.js';
import { generateInsights } from '../../analysis/insight-engine.js';
import type { WordPressOrgClient } from '../../integrations/wordpress-org-client.js';
import type { WpscanClient } from '../../integrations/wpscan-client.js';
import type { PageSpeedClient } from '../../integrations/pagespeed-client.js';
import type { Result } from '../../utils/result.js';
import type { DetectedPlugin } from '../../scanners/plugin-scanner.js';
import type { DetectedTheme } from '../../scanners/theme-scanner.js';

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
    private readonly wpscanClient: WpscanClient,
    private readonly pageSpeedClient: PageSpeedClient,
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
      const enrichmentLimitations = await Promise.all([
        this.enrichPlugins(context),
        this.enrichThemes(context),
        this.enrichCore(context),
        this.enrichPluginVulnerabilities(context),
        this.enrichThemeVulnerabilities(context),
        this.enrichCoreVulnerabilities(context),
        this.enrichPerformance(context),
      ]);
      limitations.push(...enrichmentLimitations.filter((l): l is string => l !== undefined));
    }

    const findings: Finding[] = isWordPress
      ? generateFindings(context)
      : [this.buildNotWordPressFinding(target)];
    const status: AuditStatus = limitations.length > 0 ? 'partial' : 'completed';

    const scores = calculateScores(findings);
    context.setScoreSummary(scores);

    const insights = generateInsights(findings);
    context.setInsights(insights);

    const counters = calculateReportCounters(findings);

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
      insights,
      scores,
      counters,
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

  private getScannerData<T>(context: AuditContext, scannerName: string): T | undefined {
    return getScannerData<T>(context.getScannerResults(), scannerName);
  }

  /**
   * WordPress.org lookups are prospect-safe third-party enrichment (per
   * CLAUDE.md's "what each mode may touch"), so these run regardless of
   * authorization mode. A lookup failure (network/API trouble) degrades the
   * run to 'partial'; a slug simply not being on wordpress.org
   * (closed/premium/custom) is a normal outcome and is not a limitation.
   */
  private async enrichPlugins(context: AuditContext): Promise<string | undefined> {
    const plugins = this.getScannerData<{ plugins: DetectedPlugin[] }>(
      context,
      'plugin-scanner',
    )?.plugins;
    if (!plugins) return undefined;

    return this.enrichBySlug(
      context,
      plugins,
      (slug) => this.wordPressOrgClient.getPluginInfo(slug),
      WORDPRESS_ORG_PLUGIN_ENRICHMENT,
      'wordpress-org plugin',
    );
  }

  private async enrichThemes(context: AuditContext): Promise<string | undefined> {
    const themes = this.getScannerData<{ themes: DetectedTheme[] }>(
      context,
      'theme-scanner',
    )?.themes;
    if (!themes) return undefined;

    return this.enrichBySlug(
      context,
      themes,
      (slug) => this.wordPressOrgClient.getThemeInfo(slug),
      WORDPRESS_ORG_THEME_ENRICHMENT,
      'wordpress-org theme',
    );
  }

  /** The core version -> status map is a single global lookup, cached regardless of what was detected locally. */
  private async enrichCore(context: AuditContext): Promise<string | undefined> {
    const result = await this.wordPressOrgClient.getCoreStableVersions();
    if (!result.ok) {
      this.logger.warn({ error: result.error.message }, 'wordpress-org core lookup failed');
      return 'wordpress-org core version lookup failed';
    }
    context.setEnrichment(WORDPRESS_ORG_CORE_ENRICHMENT, result.value);
    return undefined;
  }

  /**
   * WPScan CVE enrichment is audit-only per CLAUDE.md's "what each mode may
   * touch" — unlike the WordPress.org lookups above, this never runs in
   * prospect mode, regardless of whether WPSCAN_API_TOKEN is configured.
   * Also skipped when the token isn't configured at all, so a disabled
   * WPScan integration leaves no misleading "we checked, found nothing"
   * enrichment entry (the client itself would return ok([]) either way).
   */
  private async enrichPluginVulnerabilities(context: AuditContext): Promise<string | undefined> {
    if (context.authorizationMode !== 'audit' || !this.config.wpscanEnabled) return undefined;

    const plugins = this.getScannerData<{ plugins: DetectedPlugin[] }>(
      context,
      'plugin-scanner',
    )?.plugins;
    if (!plugins) return undefined;

    return this.enrichBySlug(
      context,
      plugins,
      (slug) => this.wpscanClient.getPluginVulnerabilities(slug),
      WPSCAN_PLUGIN_ENRICHMENT,
      'wpscan plugin vulnerability',
    );
  }

  private async enrichThemeVulnerabilities(context: AuditContext): Promise<string | undefined> {
    if (context.authorizationMode !== 'audit' || !this.config.wpscanEnabled) return undefined;

    const themes = this.getScannerData<{ themes: DetectedTheme[] }>(
      context,
      'theme-scanner',
    )?.themes;
    if (!themes) return undefined;

    return this.enrichBySlug(
      context,
      themes,
      (slug) => this.wpscanClient.getThemeVulnerabilities(slug),
      WPSCAN_THEME_ENRICHMENT,
      'wpscan theme vulnerability',
    );
  }

  /** Same audit-only/token gating as the plugin/theme WPScan lookups above. */
  private async enrichCoreVulnerabilities(context: AuditContext): Promise<string | undefined> {
    if (context.authorizationMode !== 'audit' || !this.config.wpscanEnabled) return undefined;

    const coreVersion = this.getScannerData<{ version: VersionInfo | undefined }>(
      context,
      'core-version-scanner',
    )?.version;
    if (!coreVersion) return undefined;

    const result = await this.wpscanClient.getCoreVulnerabilities(coreVersion.value);
    if (!result.ok) {
      this.logger.warn({ error: result.error.message }, 'wpscan core vulnerability lookup failed');
      return 'wpscan core vulnerability lookup failed';
    }
    context.setEnrichment(WPSCAN_CORE_ENRICHMENT, result.value);
    return undefined;
  }

  /**
   * PageSpeed is prospect-safe third-party enrichment (Google fetches the
   * target, not us — see CLAUDE.md's "what each mode may touch"), so this
   * runs regardless of authorization mode. Disabled entirely when
   * PAGESPEED_API_KEY isn't configured — the client itself returns
   * ok(undefined) either way, but skipping here avoids writing a
   * misleading empty enrichment entry.
   */
  private async enrichPerformance(context: AuditContext): Promise<string | undefined> {
    if (!this.config.pagespeedEnabled) return undefined;

    const homepage = context.getHttpResponse() as HttpResponse | undefined;
    if (!homepage) return undefined;

    const result = await this.pageSpeedClient.analyze(homepage.url);
    if (!result.ok) {
      this.logger.warn({ error: result.error.message }, 'PageSpeed analysis failed');
      return 'PageSpeed analysis failed';
    }
    if (result.value) {
      context.setEnrichment(PAGESPEED_ENRICHMENT, result.value);
    }
    return undefined;
  }

  private async enrichBySlug<T>(
    context: AuditContext,
    items: ReadonlyArray<{ slug: string }>,
    lookup: (slug: string) => Promise<Result<T | undefined, Error>>,
    enrichmentKey: string,
    label: string,
  ): Promise<string | undefined> {
    if (items.length === 0) return undefined;

    const lookups = await Promise.all(
      items.map(async (item) => ({ slug: item.slug, result: await lookup(item.slug) })),
    );

    const enrichment: Record<string, T | undefined> = {};
    let failureCount = 0;
    for (const { slug, result } of lookups) {
      if (result.ok) {
        enrichment[slug] = result.value;
      } else {
        failureCount += 1;
        this.logger.warn({ slug, error: result.error.message }, `${label} lookup failed`);
      }
    }

    context.setEnrichment(enrichmentKey, enrichment);
    return failureCount > 0
      ? `${label} lookup failed for ${failureCount} of ${items.length} item(s)`
      : undefined;
  }

  private buildNotWordPressFinding(target: Target): Finding {
    return createFinding({
      id: randomUUID(),
      category: 'infrastructure',
      confidence: 'confirmed',
      severity: 'info',
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
