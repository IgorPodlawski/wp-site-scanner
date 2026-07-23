import { randomUUID } from 'node:crypto';
import type { AuditContext, Finding, ScannerResult, VersionInfo } from '../core/types/index.js';
import { createFinding } from '../core/types/finding.js';
import type { HeaderScannerData, SecurityHeaderName } from '../scanners/header-scanner.js';
import type { TlsProbeResult } from '../core/http/tls-probe.js';
import type { EndpointScannerData } from '../scanners/endpoint-scanner.js';
import type { DetectedPlugin } from '../scanners/plugin-scanner.js';
import type { DetectedTheme } from '../scanners/theme-scanner.js';
import type {
  CoreStableVersions,
  WordPressOrgPluginInfo,
  WordPressOrgThemeInfo,
  WpscanVulnerability,
} from '../integrations/enrichment-types.js';
import { compareVersions } from './version-confidence.js';

// The context.setEnrichment() keys AuditOrchestrator writes to and this module reads from.
export const WORDPRESS_ORG_PLUGIN_ENRICHMENT = 'wordpress-org-plugins';
export const WORDPRESS_ORG_THEME_ENRICHMENT = 'wordpress-org-themes';
export const WORDPRESS_ORG_CORE_ENRICHMENT = 'wordpress-org-core';
export const WPSCAN_PLUGIN_ENRICHMENT = 'wpscan-plugins';
export const WPSCAN_THEME_ENRICHMENT = 'wpscan-themes';

function dataFrom<T>(results: readonly ScannerResult[], scannerName: string): T | undefined {
  const result = results.find((r) => r.scannerName === scannerName && r.status === 'ok');
  return result?.data as T | undefined;
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
        requestedSeverity: 'low',
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
        requestedSeverity: 'info',
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
        requestedSeverity: 'high',
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
        requestedSeverity: 'medium',
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
        requestedSeverity: 'medium',
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
        requestedSeverity: 'low',
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
        requestedSeverity: 'medium',
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
        requestedSeverity: 'critical',
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

interface OutdatedComponent {
  slug: string;
  version?: VersionInfo;
}

/**
 * Flags a detected plugin/theme as outdated when its version is strictly
 * older than wordpress.org's latest — only for components wordpress.org
 * actually knows about (enrichment[slug] undefined means "not found there",
 * not "up to date") and only when compareVersions can actually compare the
 * two (it abstains rather than guess on a non-numeric segment). Confidence
 * carries over from the detected version itself — WP.org's "latest" figure
 * is treated as ground truth, so the weak link is how sure we are about
 * what's actually installed, and confidence-caps-severity bounds it from there.
 */
function deriveOutdatedComponentFindings(
  components: readonly OutdatedComponent[],
  enrichment: Record<string, { version: string } | undefined>,
  messageKeyPrefix: string,
): Finding[] {
  const findings: Finding[] = [];

  for (const component of components) {
    const latest = enrichment[component.slug];
    if (!component.version || !latest) continue;

    const comparison = compareVersions(component.version.value, latest.version);
    if (comparison !== -1) continue;

    findings.push(
      createFinding({
        id: randomUUID(),
        category: 'maintenance',
        confidence: component.version.confidence,
        requestedSeverity: 'medium',
        sourceLayer: 1,
        businessImpact: 'medium',
        recommendationKey: `${messageKeyPrefix}.recommendation`,
        recommendationParams: { slug: component.slug },
        evidence: [
          {
            descriptionKey: `${messageKeyPrefix}.evidence`,
            params: {
              slug: component.slug,
              installed: component.version.value,
              latest: latest.version,
            },
          },
        ],
      }),
    );
  }

  return findings;
}

/**
 * Flags the detected core version by consulting wordpress.org's
 * version -> status map directly, rather than a numeric comparison — an
 * 'insecure' status is wordpress.org itself confirming known
 * vulnerabilities, which is why this is a 'security' finding (not
 * 'maintenance') at a higher requested severity than a plain "outdated".
 * A version absent from the map (unreleased/malformed) is left unflagged.
 */
function deriveCoreVersionFindings(
  version: VersionInfo | undefined,
  stableVersions: CoreStableVersions,
): Finding[] {
  if (!version) return [];

  const status = stableVersions[version.value];
  if (!status || status === 'latest') return [];

  const isInsecure = status === 'insecure';
  const messageKeyPrefix = isInsecure ? 'finding.core.insecure' : 'finding.core.outdated';

  return [
    createFinding({
      id: randomUUID(),
      category: isInsecure ? 'security' : 'maintenance',
      confidence: version.confidence,
      requestedSeverity: isInsecure ? 'critical' : 'medium',
      sourceLayer: 1,
      businessImpact: isInsecure ? 'strong' : 'medium',
      recommendationKey: `${messageKeyPrefix}.recommendation`,
      evidence: [
        {
          descriptionKey: `${messageKeyPrefix}.evidence`,
          params: { installed: version.value },
        },
      ],
    }),
  ];
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

/**
 * CLAUDE.md's CVE assertion rule, applied mechanically: a vulnerability is
 * only asserted as "confirmed applicable" when the component's version is
 * itself `confirmed` AND is conclusively inside the affected range.
 * Everything else that isn't conclusively patched (an unconfirmed version,
 * or a comparison that can't be resolved) is emitted as "potentially
 * affected" instead — never silently dropped, but never overclaimed either.
 * A conclusively patched install (installed >= fixedIn) is not flagged.
 */
function deriveVulnerabilityFindings(
  components: readonly OutdatedComponent[],
  vulnerabilitiesBySlug: Record<string, WpscanVulnerability[] | undefined>,
  messageKeyPrefix: string,
): Finding[] {
  const findings: Finding[] = [];

  for (const component of components) {
    const vulnerabilities = vulnerabilitiesBySlug[component.slug];
    if (!component.version || !vulnerabilities) continue;

    for (const vulnerability of vulnerabilities) {
      const affected = isAffectedByVulnerability(component.version.value, vulnerability.fixedIn);
      if (affected === 'no') continue;

      const isConfirmedApplicable =
        affected === 'yes' && component.version.confidence === 'confirmed';
      const messageKeySuffix = isConfirmedApplicable ? 'confirmed' : 'potential';

      findings.push(
        createFinding({
          id: randomUUID(),
          category: 'security',
          confidence: component.version.confidence,
          requestedSeverity: 'critical',
          sourceLayer: 'third-party',
          businessImpact: 'strong',
          recommendationKey: `${messageKeyPrefix}.${messageKeySuffix}.recommendation`,
          evidence: [
            {
              descriptionKey: `${messageKeyPrefix}.${messageKeySuffix}.evidence`,
              params: {
                slug: component.slug,
                installed: component.version.value,
                title: vulnerability.title,
              },
              raw: vulnerability,
            },
          ],
        }),
      );
    }
  }

  return findings;
}

/**
 * Interprets raw scanner observations into Findings. Never emit raw scanner
 * output directly — every Finding goes through core/types/finding.ts's
 * createFinding(), which mechanically enforces confidence-caps-severity.
 */
export function generateFindings(context: AuditContext): Finding[] {
  const results = context.getScannerResults();
  const findings: Finding[] = [];

  const headerData = dataFrom<HeaderScannerData>(results, 'header-scanner');
  if (headerData) findings.push(...deriveHeaderFindings(headerData));

  const tlsData = dataFrom<TlsProbeResult>(results, 'tls-scanner');
  if (tlsData) findings.push(...deriveTlsFindings(tlsData));

  const endpointData = dataFrom<EndpointScannerData>(results, 'endpoint-scanner');
  if (endpointData) findings.push(...deriveEndpointFindings(endpointData));

  const pluginData = dataFrom<{ plugins: DetectedPlugin[] }>(results, 'plugin-scanner');
  const pluginEnrichment = context.getEnrichment(WORDPRESS_ORG_PLUGIN_ENRICHMENT) as
    Record<string, WordPressOrgPluginInfo | undefined> | undefined;
  if (pluginData && pluginEnrichment) {
    findings.push(
      ...deriveOutdatedComponentFindings(
        pluginData.plugins,
        pluginEnrichment,
        'finding.plugin.outdated',
      ),
    );
  }

  const themeData = dataFrom<{ themes: DetectedTheme[] }>(results, 'theme-scanner');
  const themeEnrichment = context.getEnrichment(WORDPRESS_ORG_THEME_ENRICHMENT) as
    Record<string, WordPressOrgThemeInfo | undefined> | undefined;
  if (themeData && themeEnrichment) {
    findings.push(
      ...deriveOutdatedComponentFindings(
        themeData.themes,
        themeEnrichment,
        'finding.theme.outdated',
      ),
    );
  }

  const coreVersion = dataFrom<{ version: VersionInfo | undefined }>(
    results,
    'core-version-scanner',
  )?.version;
  const coreEnrichment = context.getEnrichment(WORDPRESS_ORG_CORE_ENRICHMENT) as
    CoreStableVersions | undefined;
  if (coreVersion && coreEnrichment) {
    findings.push(...deriveCoreVersionFindings(coreVersion, coreEnrichment));
  }

  const pluginVulnerabilities = context.getEnrichment(WPSCAN_PLUGIN_ENRICHMENT) as
    Record<string, WpscanVulnerability[] | undefined> | undefined;
  if (pluginData && pluginVulnerabilities) {
    findings.push(
      ...deriveVulnerabilityFindings(
        pluginData.plugins,
        pluginVulnerabilities,
        'finding.plugin.vulnerability',
      ),
    );
  }

  const themeVulnerabilities = context.getEnrichment(WPSCAN_THEME_ENRICHMENT) as
    Record<string, WpscanVulnerability[] | undefined> | undefined;
  if (themeData && themeVulnerabilities) {
    findings.push(
      ...deriveVulnerabilityFindings(
        themeData.themes,
        themeVulnerabilities,
        'finding.theme.vulnerability',
      ),
    );
  }

  return findings;
}
