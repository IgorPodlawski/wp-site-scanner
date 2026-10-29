import { randomUUID } from 'node:crypto';
import type {
  AuditContext,
  ComponentVulnerabilityInfo,
  Finding,
  FindingEvidence,
  FindingSeverity,
  ReportCounters,
  VersionInfo,
} from '../core/types/index.js';
import { createFinding } from '../core/types/finding.js';
import { getScannerData } from '../core/types/scanner.js';
import type { HeaderScannerData, SecurityHeaderName } from '../scanners/header-scanner.js';
import type { TlsProbeResult } from '../core/http/tls-probe.js';
import type { EndpointScannerData } from '../scanners/endpoint-scanner.js';
import { effectiveUrl } from '../scanners/tls-scanner.js';
import type { DetectedPlugin } from '../scanners/plugin-scanner.js';
import type { DetectedTheme } from '../scanners/theme-scanner.js';
import type {
  CoreStableVersions,
  PageSpeedResult,
  PhpVulnerability,
  WordPressOrgPluginInfo,
  WordPressOrgThemeInfo,
  WpscanVulnerability,
} from '../integrations/enrichment-types.js';
import { compareVersions, deriveConfidence, WP_VERSION_SHAPE } from './version-confidence.js';
import { getScoreBand } from './score-band.js';
import { resolveVulnerabilitySeverity } from './vulnerability-severity.js';
import { dedupeVulnerabilities } from './vulnerability-dedup.js';

// Shared by generateFindings() (so JSON output is already ranked) and html-report.ts
// (which re-applies it defensively in case a findings array ever reaches the renderer
// unsorted — e.g. hand-constructed in a test).
export const FINDING_SEVERITY_RANK: Record<FindingSeverity, number> = {
  critical: 4,
  high: 3,
  medium: 2,
  low: 1,
  info: 0,
};

/**
 * Orders findings by importance for both the persisted JSON and the report.
 * Primary key: severity tier. Within the same tier, a component with more
 * known, applicable vulnerabilities is surfaced first — e.g. an outdated
 * WordPress core with 40 itemized CVEs outranks a plugin with 3, even though
 * both land in the same severity bucket. Array.prototype.sort is stable, so
 * anything still tied (including every non-component finding, which has no
 * vulnerability list to compare) keeps its original relative order.
 */
export function compareFindingsByImportance(a: Finding, b: Finding): number {
  const severityDiff = FINDING_SEVERITY_RANK[b.severity] - FINDING_SEVERITY_RANK[a.severity];
  if (severityDiff !== 0) return severityDiff;
  const vulnCountA = a.component?.vulnerabilities.length ?? 0;
  const vulnCountB = b.component?.vulnerabilities.length ?? 0;
  return vulnCountB - vulnCountA;
}

// The context.setEnrichment() keys AuditOrchestrator writes to and this module reads from.
export const WORDPRESS_ORG_PLUGIN_ENRICHMENT = 'wordpress-org-plugins';
export const WORDPRESS_ORG_THEME_ENRICHMENT = 'wordpress-org-themes';
export const WORDPRESS_ORG_CORE_ENRICHMENT = 'wordpress-org-core';
export const WPSCAN_PLUGIN_ENRICHMENT = 'wpscan-plugins';
export const WPSCAN_THEME_ENRICHMENT = 'wpscan-themes';
export const WPSCAN_CORE_ENRICHMENT = 'wpscan-core';
export const PAGESPEED_ENRICHMENT = 'pagespeed';
export const PHP_VULNERABILITY_ENRICHMENT = 'php-vulnerabilities';

/**
 * Written once by AuditOrchestrator.run() after enrichment completes (same
 * controlled-write pattern as every other enrichment key) — 'not_assessed'
 * means the corresponding rating-engine.ts category couldn't actually check
 * anything this run (WPScan never attempted or every lookup failed, for
 * security; every wordpress.org lookup failed despite having components to
 * check, for maintenance). Read back by rating-engine.ts, never by
 * finding-engine.ts itself.
 */
export const SECURITY_COVERAGE_ENRICHMENT = 'coverage-security-wpscan';
export const MAINTENANCE_COVERAGE_ENRICHMENT = 'coverage-maintenance-wordpress-org';

/** Internal-only identifier for the core "component" — never rendered (finding.component.core.* keys don't reference {{slug}}). */
const CORE_SLUG = 'wordpress-core';
/** Same convention as CORE_SLUG — internal-only, never rendered (finding.component.php.* keys don't reference {{slug}} either). */
const PHP_SLUG = 'php';

/**
 * The only publicly visible signal of the server's PHP version — e.g.
 * `X-Powered-By: PHP/8.1.2`. Many hardened/managed hosts disable
 * `expose_php`, so this is frequently absent entirely; when it is present,
 * it's exactly one source (`http-header`), which `deriveConfidence` already
 * caps at `inferred` (same "a page cache can serve this stale" risk as a
 * bare asset `?ver=` — see version-confidence.ts). Requires the same
 * major.minor[.patch] shape as every other version extraction here.
 */
const PHP_VERSION_PATTERN = new RegExp(`PHP/(${WP_VERSION_SHAPE})`, 'i');

/** Exported so AuditOrchestrator can decide, with the exact same logic, whether there's a PHP version worth looking up at all before calling PhpVulnerabilityClient. */
export function extractPhpVersion(xPoweredBy: string | undefined): string | undefined {
  return xPoweredBy?.match(PHP_VERSION_PATTERN)?.[1];
}

const MISSING_HEADER_RULES: Array<{ header: SecurityHeaderName; key: string }> = [
  { header: 'strict-transport-security', key: 'finding.header.missingHsts' },
  { header: 'content-security-policy', key: 'finding.header.missingCsp' },
  { header: 'x-frame-options', key: 'finding.header.missingXFrameOptions' },
  { header: 'x-content-type-options', key: 'finding.header.missingXContentTypeOptions' },
];

function deriveHeaderFindings(data: HeaderScannerData): Finding[] {
  const findings: Finding[] = [];

  for (const rule of MISSING_HEADER_RULES) {
    if (data.securityHeaders[rule.header] !== undefined) continue;
    findings.push(
      createFinding({
        id: randomUUID(),
        category: 'security',
        confidence: 'confirmed',
        severity: 'low',
        sourceLayer: 1,
        businessImpact: 'weak',
        recommendationKey: `${rule.key}.recommendation`,
        evidence: [{ descriptionKey: `${rule.key}.evidence` }],
      }),
    );
  }

  for (const [header, value] of Object.entries(data.infoDisclosureHeaders)) {
    if (value === undefined) continue;
    findings.push(
      createFinding({
        id: randomUUID(),
        category: 'security',
        confidence: 'confirmed',
        severity: 'info',
        sourceLayer: 1,
        businessImpact: 'weak',
        recommendationKey: 'finding.header.infoDisclosure.recommendation',
        recommendationParams: { header },
        evidence: [
          {
            descriptionKey: 'finding.header.infoDisclosure.evidence',
            params: { header, value },
            raw: { header, value },
          },
        ],
      }),
    );
  }

  return findings;
}

const OUTDATED_TLS_PROTOCOLS = new Set(['TLSv1', 'TLSv1.1']);

/** TLS/HTTPS problems are 'infrastructure', not 'security' — matches the Infrastructure rating rule (rating-engine.ts), which is the thing that actually looks for this category. */
function deriveTlsFindings(data: TlsProbeResult): Finding[] {
  const findings: Finding[] = [];

  if (!data.authorized) {
    findings.push(
      createFinding({
        id: randomUUID(),
        category: 'infrastructure',
        confidence: 'confirmed',
        severity: 'high',
        sourceLayer: 1,
        businessImpact: 'medium',
        recommendationKey: 'finding.tls.invalidCertificate.recommendation',
        evidence: [
          {
            descriptionKey: 'finding.tls.invalidCertificate.evidence',
            params: { reason: data.authorizationError ?? 'unknown' },
            raw: data,
          },
        ],
      }),
    );
  }

  if (data.protocol && OUTDATED_TLS_PROTOCOLS.has(data.protocol)) {
    findings.push(
      createFinding({
        id: randomUUID(),
        category: 'infrastructure',
        confidence: 'confirmed',
        severity: 'medium',
        sourceLayer: 1,
        businessImpact: 'weak',
        recommendationKey: 'finding.tls.outdatedProtocol.recommendation',
        evidence: [
          {
            descriptionKey: 'finding.tls.outdatedProtocol.evidence',
            params: { protocol: data.protocol },
          },
        ],
      }),
    );
  }

  return findings;
}

/**
 * A genuinely HTTP-only site (never upgrades to HTTPS) gets no TlsProbeResult
 * at all — TlsScanner.supports() correctly skips it, since there's no TLS to
 * probe. But that left no finding of any kind for "this site has no HTTPS",
 * which is itself a real infrastructure gap. Reads the *effective* URL
 * (post-redirect — see tls-scanner.ts's `effectiveUrl`), so a site that
 * redirects http->https is correctly not flagged here (TlsScanner probes it
 * instead).
 */
function deriveHttpsFindings(context: AuditContext): Finding[] {
  if (new URL(effectiveUrl(context)).protocol === 'https:') return [];

  return [
    createFinding({
      id: randomUUID(),
      category: 'infrastructure',
      confidence: 'confirmed',
      severity: 'high',
      sourceLayer: 1,
      businessImpact: 'medium',
      recommendationKey: 'finding.infrastructure.noHttps.recommendation',
      evidence: [{ descriptionKey: 'finding.infrastructure.noHttps.evidence' }],
    }),
  ];
}

function deriveEndpointFindings(data: EndpointScannerData): Finding[] {
  const findings: Finding[] = [];

  if (data.restApiUsers.exists && data.restApiUsers.usernames?.length) {
    findings.push(
      createFinding({
        id: randomUUID(),
        category: 'security',
        confidence: 'confirmed',
        severity: 'medium',
        sourceLayer: 2,
        businessImpact: 'medium',
        recommendationKey: 'finding.endpoint.userEnumeration.recommendation',
        evidence: [
          {
            descriptionKey: 'finding.endpoint.userEnumeration.evidence',
            params: { count: data.restApiUsers.usernames.length },
            raw: data.restApiUsers.usernames,
          },
        ],
      }),
    );
  }

  if (data.xmlrpc.enabled) {
    findings.push(
      createFinding({
        id: randomUUID(),
        category: 'security',
        confidence: 'confirmed',
        severity: 'low',
        sourceLayer: 2,
        businessImpact: 'weak',
        recommendationKey: 'finding.endpoint.xmlrpcEnabled.recommendation',
        evidence: [{ descriptionKey: 'finding.endpoint.xmlrpcEnabled.evidence' }],
      }),
    );
  }

  if (data.directoryListing.listingDetected) {
    findings.push(
      createFinding({
        id: randomUUID(),
        category: 'security',
        confidence: 'confirmed',
        severity: 'medium',
        sourceLayer: 2,
        businessImpact: 'medium',
        recommendationKey: 'finding.endpoint.directoryListing.recommendation',
        evidence: [{ descriptionKey: 'finding.endpoint.directoryListing.evidence' }],
      }),
    );
  }

  const exposedBackups = data.configBackups.filter((backup) => backup.exists);
  if (exposedBackups.length > 0) {
    findings.push(
      createFinding({
        id: randomUUID(),
        category: 'security',
        confidence: 'confirmed',
        severity: 'critical',
        sourceLayer: 2,
        businessImpact: 'strong',
        recommendationKey: 'finding.endpoint.configBackupExposed.recommendation',
        evidence: [
          {
            descriptionKey: 'finding.endpoint.configBackupExposed.evidence',
            params: { paths: exposedBackups.map((backup) => backup.path).join(', ') },
            raw: exposedBackups,
          },
        ],
      }),
    );
  }

  return findings;
}

/** `WpscanVulnerability.references` flattens CVE ids and plain URLs into one array (see wpscan-client.ts). */
function formatVulnerabilityTitle(vulnerability: WpscanVulnerability): string {
  const cveIds = vulnerability.references.filter((ref) => ref.startsWith('CVE-'));
  return cveIds.length > 0 ? `${vulnerability.title} (${cveIds.join(', ')})` : vulnerability.title;
}

/** 'yes'/'no' when the fix-vs-installed comparison is conclusive, 'unknown' when it can't be determined. */
function isAffectedByVulnerability(
  installed: string,
  fixedIn: string | undefined,
): 'yes' | 'no' | 'unknown' {
  if (!fixedIn) return 'yes'; // no fix has been published yet — every known-affected install is still exposed
  const comparison = compareVersions(installed, fixedIn);
  if (comparison === undefined) return 'unknown';
  return comparison === -1 ? 'yes' : 'no';
}

/** Deduplicated, applicable-to-this-version vulnerabilities — shared by assembleComponentFinding (evidence) and generateFindings (the premium/no-.org-listing outdated fallback below), so the two never disagree about which vulnerabilities "count". */
function applicableVulnerabilities(
  installed: string,
  rawVulnerabilities: readonly WpscanVulnerability[] | undefined,
): WpscanVulnerability[] {
  return dedupeVulnerabilities(rawVulnerabilities ?? []).filter(
    (vulnerability) => isAffectedByVulnerability(installed, vulnerability.fixedIn) !== 'no',
  );
}

const SEVERITY_ORDER: readonly FindingSeverity[] = ['info', 'low', 'medium', 'high', 'critical'];

function maxSeverity(severities: readonly FindingSeverity[]): FindingSeverity {
  return severities.reduce((worst, current) =>
    SEVERITY_ORDER.indexOf(current) > SEVERITY_ORDER.indexOf(worst) ? current : worst,
  );
}

/**
 * A component with several distinct known medium-severity vulnerabilities is
 * a worse situation than one with just a single medium (or one that's merely
 * outdated with no known vulnerability at all) — but the displayed severity
 * badge was just the max, so e.g. 5 separate medium-severity CVEs looked
 * identical to "just outdated" (both 'medium'). Escalates the *badge* by one
 * tier — medium to high, never further — specifically when the max is
 * 'medium' and there are >= MEDIUM_ESCALATION_THRESHOLD of them. A single
 * high/critical vulnerability is already visible on its own merits and is
 * never escalated further by count alone (only a real CVSS >= 9.0 reaches
 * 'critical'). Rating-engine.ts's Security rule deliberately does NOT read
 * this escalated badge — it reads each vulnerability's raw severity+confirmed
 * pair directly, so a component can show "High" here while Security overall
 * stays "attention".
 */
const MEDIUM_ESCALATION_THRESHOLD = 3;

function escalateForMultipleVulnerabilities(
  severities: readonly FindingSeverity[],
): FindingSeverity {
  const max = maxSeverity(severities);
  if (max !== 'medium') return max;

  const mediumCount = severities.filter((severity) => severity === 'medium').length;
  return mediumCount >= MEDIUM_ESCALATION_THRESHOLD ? 'high' : 'medium';
}

type ComponentKind = 'core' | 'plugin' | 'theme' | 'php';

interface ComponentIdentity {
  kind: ComponentKind;
  slug: string;
  version: VersionInfo;
}

/** What to say about a component's own outdated/insecure status, independent of any itemized vulnerability list. `undefined` means "no signal either way" (e.g. wordpress.org doesn't know this slug) — never treated as "up to date". */
interface OutdatedStatus {
  evidenceKey: string;
  params: Record<string, string | number>;
}

function pluginOrThemeOutdatedStatus(
  kind: 'plugin' | 'theme',
  slug: string,
  version: VersionInfo,
  latest: string | undefined,
): OutdatedStatus | undefined {
  if (latest === undefined) return undefined;
  if (compareVersions(version.value, latest) !== -1) return undefined;
  return {
    evidenceKey: `finding.component.${kind}.outdatedStatus.evidence`,
    params: { slug, installed: version.value, latest },
  };
}

/**
 * Only ever called for a component wordpress.org has no listing for
 * (premium/closed plugins/themes — e.g. Elementor Pro) — otherwise
 * `pluginOrThemeOutdatedStatus`'s .org-based comparison is authoritative for
 * "outdated". Without wordpress.org's own "latest version" to compare
 * against, an outdated status is instead derived directly from WPScan: if
 * any applicable vulnerability has a defined `fixedIn` newer than the
 * installed version, the component is outdated *at least* relative to that
 * fix (even though the true latest release may be even newer) — the highest
 * such `fixedIn` among candidates is used as the reference point.
 */
function wpscanBasedOutdatedStatus(
  kind: 'plugin' | 'theme',
  slug: string,
  installed: string,
  applicable: readonly WpscanVulnerability[],
): OutdatedStatus | undefined {
  let bestFixedIn: string | undefined;
  for (const vulnerability of applicable) {
    if (!vulnerability.fixedIn) continue;
    if (isAffectedByVulnerability(installed, vulnerability.fixedIn) !== 'yes') continue;
    if (!bestFixedIn || compareVersions(bestFixedIn, vulnerability.fixedIn) === -1) {
      bestFixedIn = vulnerability.fixedIn;
    }
  }
  if (!bestFixedIn) return undefined;

  return {
    evidenceKey: `finding.component.${kind}.outdatedStatus.fromFixedIn.evidence`,
    params: { slug, installed, fixedIn: bestFixedIn },
  };
}

function coreOutdatedStatus(
  version: VersionInfo,
  stableVersions: CoreStableVersions,
  wpscanHasApplicableVulnerabilities: boolean,
): OutdatedStatus | undefined {
  const status = stableVersions[version.value];
  if (!status || status === 'latest') return undefined;

  // WPScan's itemized CVEs (added to the same Finding's evidence separately)
  // already convey "core has known vulnerabilities" better than this generic
  // signal — asserting it twice is redundant. Core is still tracked as
  // outdated below via the plain evidence key either way.
  const isRedundantInsecureSignal = status === 'insecure' && wpscanHasApplicableVulnerabilities;

  return {
    evidenceKey:
      status === 'insecure' && !isRedundantInsecureSignal
        ? 'finding.component.core.insecureStatus.evidence'
        : 'finding.component.core.outdatedStatus.evidence',
    params: { installed: version.value },
  };
}

/**
 * One Finding per component (WordPress core/plugin/theme), merging its
 * outdated-status and its itemized, deduplicated, applicable vulnerabilities
 * into a single result — never a separate "outdated" finding plus separate
 * per-vulnerability findings for the same underlying problem. Severity is
 * the max across applicable vulnerabilities (resolved from their own
 * CVSS/WPScan data, never from version-detection confidence), escalated from
 * 'medium' to 'high' when there are >= MEDIUM_ESCALATION_THRESHOLD of them —
 * see escalateForMultipleVulnerabilities. Confidence only ever selects
 * "confirmed"/"potential" wording per vulnerability and feeds scoring's
 * weight (see scoring-engine.ts) — it never adjusts severity. Returns
 * undefined when there is nothing to report (not outdated, no applicable
 * vulnerabilities).
 */
function assembleComponentFinding(
  component: ComponentIdentity,
  outdated: OutdatedStatus | undefined,
  rawVulnerabilities: readonly WpscanVulnerability[] | undefined,
): Finding | undefined {
  const applicable = applicableVulnerabilities(component.version.value, rawVulnerabilities);

  if (!outdated && applicable.length === 0) return undefined;

  const evidence: FindingEvidence[] = [
    {
      descriptionKey: `finding.component.${component.kind}.versionInfo.evidence`,
      params: {
        slug: component.slug,
        installed: component.version.value,
        source: component.version.sources.join(', '),
      },
    },
  ];
  if (outdated) {
    evidence.push({ descriptionKey: outdated.evidenceKey, params: outdated.params });
  }

  const vulnerabilities: ComponentVulnerabilityInfo[] = [];
  for (const vulnerability of applicable) {
    const affected = isAffectedByVulnerability(component.version.value, vulnerability.fixedIn);
    const isConfirmedApplicable =
      affected === 'yes' && component.version.confidence === 'confirmed';
    const severity = resolveVulnerabilitySeverity(vulnerability);
    vulnerabilities.push({
      severity,
      confirmed: isConfirmedApplicable,
      knownExploited: vulnerability.knownExploited ?? false,
    });

    evidence.push({
      descriptionKey: `finding.componentVulnerability.${component.kind}.${isConfirmedApplicable ? 'confirmed' : 'potential'}.evidence`,
      params: { slug: component.slug, title: formatVulnerabilityTitle(vulnerability) },
      raw: vulnerability,
    });
  }

  const hasVulnerabilities = vulnerabilities.length > 0;

  return createFinding({
    id: randomUUID(),
    category: hasVulnerabilities ? 'security' : 'maintenance',
    confidence: component.version.confidence,
    severity: hasVulnerabilities
      ? escalateForMultipleVulnerabilities(vulnerabilities.map((v) => v.severity))
      : 'medium',
    sourceLayer: 'third-party',
    businessImpact: hasVulnerabilities ? 'strong' : 'medium',
    recommendationKey: `finding.component.${component.kind}.${hasVulnerabilities ? 'vulnerable' : 'outdated'}.recommendation`,
    recommendationParams: { slug: component.slug },
    evidence,
    component: {
      kind: component.kind,
      slug: component.slug,
      isOutdated: outdated !== undefined,
      vulnerabilities,
    },
  });
}

/**
 * Flags a low mobile PageSpeed performance score. `confidence: 'confirmed'`
 * — this is Google's own Lighthouse measurement of this exact URL, not an
 * inference, so it earns the same trust tier as e.g. wordpress.org's
 * stable-check map. Only one finding per audit (never one per Core Web
 * Vital) — the individual LCP/CLS/INP numbers live in `raw` for the JSON
 * report, not as separate findings, per "three meaningful findings beat
 * fifty weak ones." Uses the same 0-100 good/fair/poor bands the scores
 * section of the report shows, so "poor" here means the same thing it does
 * there.
 */
function derivePerformanceFindings(result: PageSpeedResult): Finding[] {
  const band = getScoreBand(result.performanceScore);
  if (band === 'good') return [];

  const isPoor = band === 'poor';
  const messageKeyPrefix = isPoor
    ? 'finding.performance.poor'
    : 'finding.performance.needsImprovement';

  return [
    createFinding({
      id: randomUUID(),
      category: 'performance',
      confidence: 'confirmed',
      severity: isPoor ? 'high' : 'medium',
      sourceLayer: 'third-party',
      businessImpact: isPoor ? 'medium' : 'weak',
      recommendationKey: `${messageKeyPrefix}.recommendation`,
      evidence: [
        {
          descriptionKey: `${messageKeyPrefix}.evidence`,
          params: { score: result.performanceScore },
          raw: result.coreWebVitals,
        },
      ],
    }),
  ];
}

/**
 * Interprets raw scanner observations into Findings. Never emit raw scanner
 * output directly — every Finding goes through core/types/finding.ts's
 * createFinding().
 */
export function generateFindings(context: AuditContext): Finding[] {
  const results = context.getScannerResults();
  const findings: Finding[] = [];

  const headerData = getScannerData<HeaderScannerData>(results, 'header-scanner');
  if (headerData) findings.push(...deriveHeaderFindings(headerData));

  const phpVersionValue = extractPhpVersion(headerData?.infoDisclosureHeaders['x-powered-by']);
  if (phpVersionValue) {
    const phpVersion: VersionInfo = {
      value: phpVersionValue,
      sources: ['http-header'],
      confidence: deriveConfidence(['http-header']),
    };
    const phpVulnerabilities = context.getEnrichment(PHP_VULNERABILITY_ENRICHMENT) as
      PhpVulnerability[] | undefined;
    const phpFinding = assembleComponentFinding(
      { kind: 'php', slug: PHP_SLUG, version: phpVersion },
      undefined,
      phpVulnerabilities,
    );
    if (phpFinding) findings.push(phpFinding);
  }

  const tlsData = getScannerData<TlsProbeResult>(results, 'tls-scanner');
  if (tlsData) findings.push(...deriveTlsFindings(tlsData));
  findings.push(...deriveHttpsFindings(context));

  const endpointData = getScannerData<EndpointScannerData>(results, 'endpoint-scanner');
  if (endpointData) findings.push(...deriveEndpointFindings(endpointData));

  const pluginData = getScannerData<{ plugins: DetectedPlugin[] }>(results, 'plugin-scanner');
  const pluginEnrichment = context.getEnrichment(WORDPRESS_ORG_PLUGIN_ENRICHMENT) as
    Record<string, WordPressOrgPluginInfo | undefined> | undefined;
  const pluginVulnerabilities = context.getEnrichment(WPSCAN_PLUGIN_ENRICHMENT) as
    Record<string, WpscanVulnerability[] | undefined> | undefined;
  for (const plugin of pluginData?.plugins ?? []) {
    if (!plugin.version) continue;
    const latest = pluginEnrichment?.[plugin.slug]?.version;
    const rawVulnerabilities = pluginVulnerabilities?.[plugin.slug];
    const outdated =
      pluginOrThemeOutdatedStatus('plugin', plugin.slug, plugin.version, latest) ??
      // No .org listing at all (premium/closed plugin) — fall back to WPScan's
      // own fixed_in data rather than never flagging it as outdated.
      (latest === undefined
        ? wpscanBasedOutdatedStatus(
            'plugin',
            plugin.slug,
            plugin.version.value,
            applicableVulnerabilities(plugin.version.value, rawVulnerabilities),
          )
        : undefined);
    const finding = assembleComponentFinding(
      { kind: 'plugin', slug: plugin.slug, version: plugin.version },
      outdated,
      rawVulnerabilities,
    );
    if (finding) findings.push(finding);
  }

  const themeData = getScannerData<{ themes: DetectedTheme[] }>(results, 'theme-scanner');
  const themeEnrichment = context.getEnrichment(WORDPRESS_ORG_THEME_ENRICHMENT) as
    Record<string, WordPressOrgThemeInfo | undefined> | undefined;
  const themeVulnerabilities = context.getEnrichment(WPSCAN_THEME_ENRICHMENT) as
    Record<string, WpscanVulnerability[] | undefined> | undefined;
  for (const theme of themeData?.themes ?? []) {
    if (!theme.version) continue;
    const latest = themeEnrichment?.[theme.slug]?.version;
    const rawVulnerabilities = themeVulnerabilities?.[theme.slug];
    const outdated =
      pluginOrThemeOutdatedStatus('theme', theme.slug, theme.version, latest) ??
      (latest === undefined
        ? wpscanBasedOutdatedStatus(
            'theme',
            theme.slug,
            theme.version.value,
            applicableVulnerabilities(theme.version.value, rawVulnerabilities),
          )
        : undefined);
    const finding = assembleComponentFinding(
      { kind: 'theme', slug: theme.slug, version: theme.version },
      outdated,
      rawVulnerabilities,
    );
    if (finding) findings.push(finding);
  }

  const coreVersion = getScannerData<{ version: VersionInfo | undefined }>(
    results,
    'core-version-scanner',
  )?.version;
  if (coreVersion) {
    const coreEnrichment = context.getEnrichment(WORDPRESS_ORG_CORE_ENRICHMENT) as
      CoreStableVersions | undefined;
    const coreVulnerabilities = context.getEnrichment(WPSCAN_CORE_ENRICHMENT) as
      WpscanVulnerability[] | undefined;
    const hasApplicableCoreVulnerabilities =
      applicableVulnerabilities(coreVersion.value, coreVulnerabilities).length > 0;
    const outdated = coreEnrichment
      ? coreOutdatedStatus(coreVersion, coreEnrichment, hasApplicableCoreVulnerabilities)
      : undefined;
    const finding = assembleComponentFinding(
      { kind: 'core', slug: CORE_SLUG, version: coreVersion },
      outdated,
      coreVulnerabilities,
    );
    if (finding) findings.push(finding);
  }

  const pageSpeedResult = context.getEnrichment(PAGESPEED_ENRICHMENT) as
    PageSpeedResult | undefined;
  if (pageSpeedResult) {
    findings.push(...derivePerformanceFindings(pageSpeedResult));
  }

  return findings.sort(compareFindingsByImportance);
}

const VULNERABILITY_EVIDENCE_PREFIX = 'finding.componentVulnerability.';

/**
 * Report-wide counts derived from the final Finding list, computed once so
 * the report and any insight built on it always agree on the same numbers.
 * `uniqueVulnerabilityCount` deduplicates across every component (not just
 * within one) — the same CVE affecting both a plugin and WordPress core
 * counts once here, even though it legitimately appears in both findings.
 */
export function calculateReportCounters(findings: readonly Finding[]): ReportCounters {
  const componentFindings = findings.filter((finding) => finding.component);

  const allVulnerabilities = componentFindings.flatMap((finding) =>
    finding.evidence
      .filter((evidence) => evidence.descriptionKey.startsWith(VULNERABILITY_EVIDENCE_PREFIX))
      .map((evidence) => evidence.raw as WpscanVulnerability),
  );

  const findingsBySeverity: Record<FindingSeverity, number> = {
    info: 0,
    low: 0,
    medium: 0,
    high: 0,
    critical: 0,
  };
  for (const finding of findings) {
    findingsBySeverity[finding.severity] += 1;
  }

  return {
    componentsWithVulnerabilities: componentFindings.filter(
      (finding) => finding.component!.vulnerabilities.length > 0,
    ).length,
    uniqueVulnerabilityCount: dedupeVulnerabilities(allVulnerabilities).length,
    outdatedComponentCount: componentFindings.filter((finding) => finding.component!.isOutdated)
      .length,
    findingsBySeverity,
  };
}
