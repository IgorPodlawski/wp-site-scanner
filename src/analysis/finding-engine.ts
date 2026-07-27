import { randomUUID } from 'node:crypto';
import type {
  AuditContext,
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
import type { DetectedPlugin } from '../scanners/plugin-scanner.js';
import type { DetectedTheme } from '../scanners/theme-scanner.js';
import type {
  CoreStableVersions,
  PageSpeedResult,
  WordPressOrgPluginInfo,
  WordPressOrgThemeInfo,
  WpscanVulnerability,
} from '../integrations/enrichment-types.js';
import { compareVersions } from './version-confidence.js';
import { getScoreBand } from './score-band.js';
import { resolveVulnerabilitySeverity } from './vulnerability-severity.js';
import { dedupeVulnerabilities } from './vulnerability-dedup.js';

// The context.setEnrichment() keys AuditOrchestrator writes to and this module reads from.
export const WORDPRESS_ORG_PLUGIN_ENRICHMENT = 'wordpress-org-plugins';
export const WORDPRESS_ORG_THEME_ENRICHMENT = 'wordpress-org-themes';
export const WORDPRESS_ORG_CORE_ENRICHMENT = 'wordpress-org-core';
export const WPSCAN_PLUGIN_ENRICHMENT = 'wpscan-plugins';
export const WPSCAN_THEME_ENRICHMENT = 'wpscan-themes';
export const WPSCAN_CORE_ENRICHMENT = 'wpscan-core';
export const PAGESPEED_ENRICHMENT = 'pagespeed';

/** Internal-only identifier for the core "component" — never rendered (finding.component.core.* keys don't reference {{slug}}). */
const CORE_SLUG = 'wordpress-core';

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

function deriveTlsFindings(data: TlsProbeResult): Finding[] {
  const findings: Finding[] = [];

  if (!data.authorized) {
    findings.push(
      createFinding({
        id: randomUUID(),
        category: 'security',
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
        category: 'security',
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

const SEVERITY_ORDER: readonly FindingSeverity[] = ['info', 'low', 'medium', 'high', 'critical'];

function maxSeverity(severities: readonly FindingSeverity[]): FindingSeverity {
  return severities.reduce((worst, current) =>
    SEVERITY_ORDER.indexOf(current) > SEVERITY_ORDER.indexOf(worst) ? current : worst,
  );
}

type ComponentKind = 'core' | 'plugin' | 'theme';

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

function coreOutdatedStatus(
  version: VersionInfo,
  stableVersions: CoreStableVersions,
): OutdatedStatus | undefined {
  const status = stableVersions[version.value];
  if (!status || status === 'latest') return undefined;
  return {
    evidenceKey:
      status === 'insecure'
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
 * CVSS/WPScan data, never from version-detection confidence); confidence
 * only ever selects "confirmed"/"potential" wording per vulnerability and
 * feeds scoring's weight (see scoring-engine.ts) — it never adjusts severity.
 * Returns undefined when there is nothing to report (not outdated, no
 * applicable vulnerabilities).
 */
function assembleComponentFinding(
  component: ComponentIdentity,
  outdated: OutdatedStatus | undefined,
  vulnerabilities: readonly WpscanVulnerability[] | undefined,
): Finding | undefined {
  const applicable = dedupeVulnerabilities(vulnerabilities ?? []).filter(
    (vulnerability) =>
      isAffectedByVulnerability(component.version.value, vulnerability.fixedIn) !== 'no',
  );

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

  const vulnerabilitySeverities: FindingSeverity[] = [];
  for (const vulnerability of applicable) {
    const affected = isAffectedByVulnerability(component.version.value, vulnerability.fixedIn);
    const isConfirmedApplicable =
      affected === 'yes' && component.version.confidence === 'confirmed';
    const severity = resolveVulnerabilitySeverity(vulnerability);
    vulnerabilitySeverities.push(severity);

    evidence.push({
      descriptionKey: `finding.componentVulnerability.${component.kind}.${isConfirmedApplicable ? 'confirmed' : 'potential'}.evidence`,
      params: { slug: component.slug, title: formatVulnerabilityTitle(vulnerability) },
      raw: vulnerability,
    });
  }

  const hasVulnerabilities = vulnerabilitySeverities.length > 0;

  return createFinding({
    id: randomUUID(),
    category: hasVulnerabilities ? 'security' : 'maintenance',
    confidence: component.version.confidence,
    severity: hasVulnerabilities ? maxSeverity(vulnerabilitySeverities) : 'medium',
    sourceLayer: 'third-party',
    businessImpact: hasVulnerabilities ? 'strong' : 'medium',
    recommendationKey: `finding.component.${component.kind}.${hasVulnerabilities ? 'vulnerable' : 'outdated'}.recommendation`,
    recommendationParams: { slug: component.slug },
    evidence,
    component: {
      kind: component.kind,
      slug: component.slug,
      isOutdated: outdated !== undefined,
      vulnerabilitySeverities,
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

  const tlsData = getScannerData<TlsProbeResult>(results, 'tls-scanner');
  if (tlsData) findings.push(...deriveTlsFindings(tlsData));

  const endpointData = getScannerData<EndpointScannerData>(results, 'endpoint-scanner');
  if (endpointData) findings.push(...deriveEndpointFindings(endpointData));

  const pluginData = getScannerData<{ plugins: DetectedPlugin[] }>(results, 'plugin-scanner');
  const pluginEnrichment = context.getEnrichment(WORDPRESS_ORG_PLUGIN_ENRICHMENT) as
    Record<string, WordPressOrgPluginInfo | undefined> | undefined;
  const pluginVulnerabilities = context.getEnrichment(WPSCAN_PLUGIN_ENRICHMENT) as
    Record<string, WpscanVulnerability[] | undefined> | undefined;
  for (const plugin of pluginData?.plugins ?? []) {
    if (!plugin.version) continue;
    const outdated = pluginOrThemeOutdatedStatus(
      'plugin',
      plugin.slug,
      plugin.version,
      pluginEnrichment?.[plugin.slug]?.version,
    );
    const finding = assembleComponentFinding(
      { kind: 'plugin', slug: plugin.slug, version: plugin.version },
      outdated,
      pluginVulnerabilities?.[plugin.slug],
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
    const outdated = pluginOrThemeOutdatedStatus(
      'theme',
      theme.slug,
      theme.version,
      themeEnrichment?.[theme.slug]?.version,
    );
    const finding = assembleComponentFinding(
      { kind: 'theme', slug: theme.slug, version: theme.version },
      outdated,
      themeVulnerabilities?.[theme.slug],
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
    const outdated = coreEnrichment ? coreOutdatedStatus(coreVersion, coreEnrichment) : undefined;
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

  return findings;
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
      (finding) => finding.component!.vulnerabilitySeverities.length > 0,
    ).length,
    uniqueVulnerabilityCount: dedupeVulnerabilities(allVulnerabilities).length,
    outdatedComponentCount: componentFindings.filter((finding) => finding.component!.isOutdated)
      .length,
    findingsBySeverity,
  };
}
