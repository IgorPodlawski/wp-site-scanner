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
  extractPhpVersion,
  WORDPRESS_ORG_PLUGIN_ENRICHMENT,
  WORDPRESS_ORG_THEME_ENRICHMENT,
  WORDPRESS_ORG_CORE_ENRICHMENT,
  WPSCAN_PLUGIN_ENRICHMENT,
  WPSCAN_THEME_ENRICHMENT,
  WPSCAN_CORE_ENRICHMENT,
  PAGESPEED_ENRICHMENT,
  PHP_VULNERABILITY_ENRICHMENT,
  SECURITY_COVERAGE_ENRICHMENT,
  MAINTENANCE_COVERAGE_ENRICHMENT,
} from '../../analysis/finding-engine.js';
import { calculateMeasuredScores } from '../../analysis/scoring-engine.js';
import { calculateRatings } from '../../analysis/rating-engine.js';
import { generateInsights } from '../../analysis/insight-engine.js';
import type { WordPressOrgClient } from '../../integrations/wordpress-org-client.js';
import type { WpscanClient } from '../../integrations/wpscan-client.js';
import type { PageSpeedClient } from '../../integrations/pagespeed-client.js';
import type { PhpVulnerabilityClient } from '../../integrations/php-vulnerability-client.js';
import type { PageSpeedResult } from '../../integrations/enrichment-types.js';
import type { Result } from '../../utils/result.js';
import type { DetectedPlugin } from '../../scanners/plugin-scanner.js';
import type { DetectedTheme } from '../../scanners/theme-scanner.js';
import type { HeaderScannerData } from '../../scanners/header-scanner.js';

const AUTH_RANK: Record<AuthorizationMode, number> = { prospect: 0, audit: 1 };

/**
 * How much of an enrichment track (WordPress.org for maintenance, WPScan for
 * security) actually got checked this run — used to compute the
 * SECURITY_COVERAGE_ENRICHMENT/MAINTENANCE_COVERAGE_ENRICHMENT flags
 * rating-engine.ts reads. `attempted`/`succeeded` are counts across every
 * item checked (a "not found on wordpress.org" for one premium plugin still
 * counts as a success — the lookup itself worked, it just had nothing to
 * report), aggregated across plugin+theme+core calls.
 */
interface EnrichmentOutcome {
  attempted: number;
  succeeded: number;
  limitation?: string;
}

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
    private readonly phpVulnerabilityClient: PhpVulnerabilityClient,
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
    let pageSpeedResult: PageSpeedResult | undefined;
    if (isWordPress) {
      const [
        orgPlugins,
        orgThemes,
        orgCore,
        wpscanPlugins,
        wpscanThemes,
        wpscanCore,
        perfLimitation,
        phpLimitation,
      ] = await Promise.all([
        this.enrichPlugins(context),
        this.enrichThemes(context),
        this.enrichCore(context),
        this.enrichPluginVulnerabilities(context),
        this.enrichThemeVulnerabilities(context),
        this.enrichCoreVulnerabilities(context),
        this.enrichPerformance(context),
        this.enrichPhpVulnerabilities(context),
      ]);

      const orgOutcomes = [orgPlugins, orgThemes, orgCore];
      const wpscanOutcomes = [wpscanPlugins, wpscanThemes, wpscanCore];
      limitations.push(
        ...[...orgOutcomes, ...wpscanOutcomes]
          .map((outcome) => outcome.limitation)
          .filter((l): l is string => l !== undefined),
        ...(perfLimitation ? [perfLimitation] : []),
        ...(phpLimitation ? [phpLimitation] : []),
      );

      // WPScan is gated off entirely in prospect mode / without a token — that
      // must read as not_assessed even when there was nothing to check
      // (attempted === 0), unlike wordpress.org, which is always attempted
      // regardless of mode and only becomes not_assessed via total failure.
      const wpscanEligible = context.authorizationMode === 'audit' && this.config.wpscanEnabled;
      context.setEnrichment(MAINTENANCE_COVERAGE_ENRICHMENT, this.computeCoverage(orgOutcomes));
      context.setEnrichment(
        SECURITY_COVERAGE_ENRICHMENT,
        wpscanEligible ? this.computeCoverage(wpscanOutcomes) : 'not_assessed',
      );

      pageSpeedResult = context.getEnrichment(PAGESPEED_ENRICHMENT) as PageSpeedResult | undefined;
    }

    const findings: Finding[] = isWordPress
      ? generateFindings(context)
      : [this.buildNotWordPressFinding(target)];
    const status: AuditStatus = limitations.length > 0 ? 'partial' : 'completed';

    const insights = generateInsights(findings);
    context.setInsights(insights);

    const counters = calculateReportCounters(findings);
    const ratings = isWordPress ? calculateRatings(context, findings, counters) : undefined;
    const measuredScores = calculateMeasuredScores(pageSpeedResult);

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
      ...(ratings ? { ratings } : {}),
      measuredScores,
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
  private async enrichPlugins(context: AuditContext): Promise<EnrichmentOutcome> {
    const plugins = this.getScannerData<{ plugins: DetectedPlugin[] }>(
      context,
      'plugin-scanner',
    )?.plugins;
    if (!plugins) return { attempted: 0, succeeded: 0 };

    return this.enrichBySlug(
      context,
      plugins,
      (slug) => this.wordPressOrgClient.getPluginInfo(slug),
      WORDPRESS_ORG_PLUGIN_ENRICHMENT,
      'wordpress-org plugin',
    );
  }

  private async enrichThemes(context: AuditContext): Promise<EnrichmentOutcome> {
    const themes = this.getScannerData<{ themes: DetectedTheme[] }>(
      context,
      'theme-scanner',
    )?.themes;
    if (!themes) return { attempted: 0, succeeded: 0 };

    return this.enrichBySlug(
      context,
      themes,
      (slug) => this.wordPressOrgClient.getThemeInfo(slug),
      WORDPRESS_ORG_THEME_ENRICHMENT,
      'wordpress-org theme',
    );
  }

  /** The core version -> status map is a single global lookup, cached regardless of what was detected locally. */
  private async enrichCore(context: AuditContext): Promise<EnrichmentOutcome> {
    const result = await this.wordPressOrgClient.getCoreStableVersions();
    if (!result.ok) {
      this.logger.warn({ error: result.error.message }, 'wordpress-org core lookup failed');
      return { attempted: 1, succeeded: 0, limitation: 'wordpress-org core version lookup failed' };
    }
    context.setEnrichment(WORDPRESS_ORG_CORE_ENRICHMENT, result.value);
    return { attempted: 1, succeeded: 1 };
  }

  /**
   * Aggregates attempted/succeeded across plugin+theme+core calls for one
   * enrichment track (WordPress.org or WPScan) into the binary signal
   * rating-engine.ts actually needs: `not_assessed` only when there was
   * something to check and *every single* lookup failed; `assessed`
   * otherwise (including the vacuous case of nothing to check at all).
   */
  private computeCoverage(outcomes: readonly EnrichmentOutcome[]): 'assessed' | 'not_assessed' {
    const attempted = outcomes.reduce((sum, outcome) => sum + outcome.attempted, 0);
    const succeeded = outcomes.reduce((sum, outcome) => sum + outcome.succeeded, 0);
    return attempted > 0 && succeeded === 0 ? 'not_assessed' : 'assessed';
  }

  /**
   * WPScan CVE enrichment is audit-only per CLAUDE.md's "what each mode may
   * touch" — unlike the WordPress.org lookups above, this never runs in
   * prospect mode, regardless of whether WPSCAN_API_TOKEN is configured.
   * Also skipped when the token isn't configured at all, so a disabled
   * WPScan integration leaves no misleading "we checked, found nothing"
   * enrichment entry (the client itself would return ok([]) either way).
   */
  private async enrichPluginVulnerabilities(context: AuditContext): Promise<EnrichmentOutcome> {
    if (context.authorizationMode !== 'audit' || !this.config.wpscanEnabled) {
      return { attempted: 0, succeeded: 0 };
    }

    const plugins = this.getScannerData<{ plugins: DetectedPlugin[] }>(
      context,
      'plugin-scanner',
    )?.plugins;
    if (!plugins) return { attempted: 0, succeeded: 0 };

    return this.enrichBySlug(
      context,
      plugins,
      (slug) => this.wpscanClient.getPluginVulnerabilities(slug),
      WPSCAN_PLUGIN_ENRICHMENT,
      'wpscan plugin vulnerability',
    );
  }

  private async enrichThemeVulnerabilities(context: AuditContext): Promise<EnrichmentOutcome> {
    if (context.authorizationMode !== 'audit' || !this.config.wpscanEnabled) {
      return { attempted: 0, succeeded: 0 };
    }

    const themes = this.getScannerData<{ themes: DetectedTheme[] }>(
      context,
      'theme-scanner',
    )?.themes;
    if (!themes) return { attempted: 0, succeeded: 0 };

    return this.enrichBySlug(
      context,
      themes,
      (slug) => this.wpscanClient.getThemeVulnerabilities(slug),
      WPSCAN_THEME_ENRICHMENT,
      'wpscan theme vulnerability',
    );
  }

  /** Same audit-only/token gating as the plugin/theme WPScan lookups above. */
  private async enrichCoreVulnerabilities(context: AuditContext): Promise<EnrichmentOutcome> {
    if (context.authorizationMode !== 'audit' || !this.config.wpscanEnabled) {
      return { attempted: 0, succeeded: 0 };
    }

    const coreVersion = this.getScannerData<{ version: VersionInfo | undefined }>(
      context,
      'core-version-scanner',
    )?.version;
    if (!coreVersion) return { attempted: 0, succeeded: 0 };

    const result = await this.wpscanClient.getCoreVulnerabilities(coreVersion.value);
    if (!result.ok) {
      this.logger.warn({ error: result.error.message }, 'wpscan core vulnerability lookup failed');
      return { attempted: 1, succeeded: 0, limitation: 'wpscan core vulnerability lookup failed' };
    }
    context.setEnrichment(WPSCAN_CORE_ENRICHMENT, result.value);
    return { attempted: 1, succeeded: 1 };
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

  /**
   * Prospect-safe (same category as WordPress.org/PageSpeed — a public
   * third-party lookup about PHP in general, not extra probing of the
   * target) — runs regardless of authorization mode, unlike WPScan. Only
   * attempted at all when the homepage response actually leaked a PHP
   * version via `X-Powered-By`, which most hardened/managed hosts disable;
   * silently skipped (not a limitation) when it's absent, since there is
   * nothing to look up.
   */
  private async enrichPhpVulnerabilities(context: AuditContext): Promise<string | undefined> {
    const headerData = this.getScannerData<HeaderScannerData>(context, 'header-scanner');
    const phpVersion = extractPhpVersion(headerData?.infoDisclosureHeaders['x-powered-by']);
    if (!phpVersion) return undefined;

    const result = await this.phpVulnerabilityClient.getVulnerabilities(phpVersion);
    if (!result.ok) {
      this.logger.warn({ error: result.error.message }, 'PHP vulnerability lookup failed');
      return 'PHP vulnerability lookup failed';
    }
    context.setEnrichment(PHP_VULNERABILITY_ENRICHMENT, result.value);
    return undefined;
  }

  private async enrichBySlug<T>(
    context: AuditContext,
    items: ReadonlyArray<{ slug: string }>,
    lookup: (slug: string) => Promise<Result<T | undefined, Error>>,
    enrichmentKey: string,
    label: string,
  ): Promise<EnrichmentOutcome> {
    if (items.length === 0) return { attempted: 0, succeeded: 0 };

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
    return {
      attempted: items.length,
      succeeded: items.length - failureCount,
      ...(failureCount > 0
        ? { limitation: `${label} lookup failed for ${failureCount} of ${items.length} item(s)` }
        : {}),
    };
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
