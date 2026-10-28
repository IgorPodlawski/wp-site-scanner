import type {
  AuditContext,
  CategoryRating,
  ComponentVulnerabilityInfo,
  Finding,
  RatingLevel,
  RatingReason,
  RatingSummary,
  ReportCounters,
} from '../core/types/index.js';
import { getScannerData } from '../core/types/scanner.js';
import type { TlsProbeResult } from '../core/http/tls-probe.js';
import { effectiveUrl } from '../scanners/tls-scanner.js';
import { SECURITY_COVERAGE_ENRICHMENT, MAINTENANCE_COVERAGE_ENRICHMENT } from './finding-engine.js';

/**
 * How ratings are decided, in one place, as plain first-match rules — no
 * hidden weights, no arithmetic. Every rule follows the same shape: a
 * finding-based signal always wins first (if we found something, say so);
 * `not_assessed` is only the fallback when *nothing* was found *and* we
 * know the relevant check never actually ran this run (a missing WPScan
 * token, a totally-failed wordpress.org lookup, prospect mode, a TLS probe
 * that errored). This avoids the trap of a category reading `clear` purely
 * because the check that would have found a problem never ran.
 *
 * Takes `context: AuditContext` directly (not a bespoke data shape) — the
 * same convention finding-engine.ts already uses for reading scanner
 * results/enrichment. "Pure" here means no I/O and no mutation, not
 * "context-free"; this module still does zero fetching or side effects of
 * its own.
 */

export const MAINTENANCE_URGENT_OUTDATED = 6;

const HIGH_SEVERITIES = new Set(['high', 'critical']);

type Coverage = 'assessed' | 'not_assessed';

function coverageOf(context: AuditContext, key: string): Coverage {
  return (context.getEnrichment(key) as Coverage | undefined) ?? 'not_assessed';
}

function isEndpointFinding(finding: Finding): boolean {
  return finding.recommendationKey.startsWith('finding.endpoint.');
}

const ENDPOINT_REASON_KEYS: Record<string, string> = {
  'finding.endpoint.userEnumeration.recommendation': 'rating.security.reason.userEnumeration',
  'finding.endpoint.xmlrpcEnabled.recommendation': 'rating.security.reason.xmlrpcEnabled',
  'finding.endpoint.directoryListing.recommendation': 'rating.security.reason.directoryListing',
  'finding.endpoint.configBackupExposed.recommendation':
    'rating.security.reason.configBackupExposed',
};

function endpointReason(finding: Finding): RatingReason {
  return {
    key:
      ENDPOINT_REASON_KEYS[finding.recommendationKey] ?? 'rating.security.reason.exposedEndpoint',
    params: { severity: finding.severity },
  };
}

function vulnerabilityReason(vulnerability: ComponentVulnerabilityInfo): RatingReason {
  const key = vulnerability.knownExploited
    ? 'rating.security.reason.knownExploitedVulnerability'
    : vulnerability.confirmed
      ? 'rating.security.reason.confirmedVulnerability'
      : 'rating.security.reason.potentialVulnerability';
  return { key, params: { severity: vulnerability.severity } };
}

/**
 * Depends ONLY on actual vulnerabilities (WPScan/NVD component data) and
 * endpoint-scanner exposures (config backup, xmlrpc, user enumeration,
 * directory listing) — never on missing security headers (those are
 * hygiene, see html-report.ts's hygiene section / insight-engine.ts). The
 * `urgent` threshold reads each vulnerability's *raw* confirmed+severity
 * pair, never the component Finding's own escalated severity badge — a
 * component can show "High" on its badge (escalated from several mediums,
 * see finding-engine.ts) while Security here stays `attention`, by design.
 *
 * `knownExploited` (PHP vulnerabilities only, cross-referenced against
 * CISA's KEV catalog — see `php-vulnerability-client.ts`) is treated as
 * urgent-eligible exactly like `confirmed`, even when `confirmed` itself is
 * `false`. PHP's version can only ever come from a single header source
 * (`X-Powered-By`), which `deriveConfidence` already caps at `inferred` —
 * meaning a PHP vulnerability's `confirmed` flag is realistically *never*
 * `true` on its own. CISA's own confirmation that a CVE is being actively
 * exploited in the wild is a stronger, independent signal than our own
 * version-detection confidence, so it earns the same threshold rather than
 * being permanently capped at `attention` regardless of severity.
 */
export function rateSecurity(context: AuditContext, findings: readonly Finding[]): CategoryRating {
  const vulnerabilities = findings.flatMap((finding) => finding.component?.vulnerabilities ?? []);
  const endpointFindings = findings.filter(isEndpointFinding);

  const urgentVulnerabilities = vulnerabilities.filter(
    (v) => (v.confirmed || v.knownExploited) && HIGH_SEVERITIES.has(v.severity),
  );
  const urgentEndpoints = endpointFindings.filter((f) => HIGH_SEVERITIES.has(f.severity));

  if (urgentVulnerabilities.length > 0 || urgentEndpoints.length > 0) {
    return {
      category: 'security',
      level: 'urgent',
      reasons: [
        ...urgentVulnerabilities.map(vulnerabilityReason),
        ...urgentEndpoints.map(endpointReason),
      ],
    };
  }

  if (vulnerabilities.length > 0 || endpointFindings.length > 0) {
    const reasons: RatingReason[] = [];
    if (vulnerabilities.length > 0) {
      reasons.push({
        key: 'rating.security.reason.potentialVulnerabilities',
        params: { count: vulnerabilities.length },
      });
    }
    if (endpointFindings.length > 0) {
      reasons.push(...endpointFindings.map(endpointReason));
    }
    return { category: 'security', level: 'attention', reasons };
  }

  if (coverageOf(context, SECURITY_COVERAGE_ENRICHMENT) === 'not_assessed') {
    return {
      category: 'security',
      level: 'not_assessed',
      reasons: [{ key: 'rating.security.reason.notAssessed' }],
    };
  }

  return {
    category: 'security',
    level: 'clear',
    reasons: [{ key: 'rating.security.reason.clear' }],
  };
}

/**
 * Outdated-ness is a separate axis from vulnerabilities (a component can be
 * outdated with zero known CVEs, or vulnerable without wordpress.org even
 * knowing about it — see finding-engine.ts's WPScan/.org decoupling).
 *
 * The `urgent` threshold requires `confidence !== 'inferred'` — the same bar
 * Security's `urgent` threshold already applies to vulnerabilities (raw
 * confirmed+severity, never a mere "potential" match). An `inferred` version
 * comes from a single, un-corroborated signal (typically a bare asset
 * `?ver=`), which "cache-busters lie" (see CLAUDE.md's Version detection
 * rules) already warns can be wrong — found live: a real client site's
 * cached homepage still referenced `?ver=6.5.4` after the site had actually
 * been upgraded to 7.0.3 (confirmed via wp-admin), because the page cache
 * hadn't been purged since the upgrade. Asserting "core is outdated, urgent"
 * off that alone is exactly the kind of false positive CLAUDE.md's "false
 * positives are worse than missed findings" warns against. `attention`
 * still applies regardless of confidence — the signal is still worth a
 * softer, non-headline note even when unconfirmed.
 */
export function rateMaintenance(
  context: AuditContext,
  findings: readonly Finding[],
  counters: ReportCounters,
): CategoryRating {
  const outdatedFindings = findings.filter((finding) => finding.component?.isOutdated);
  const confidentlyOutdated = outdatedFindings.filter(
    (finding) => finding.confidence !== 'inferred',
  );
  const coreOutdatedConfidently = confidentlyOutdated.some(
    (finding) => finding.component?.kind === 'core',
  );
  const outdatedCount = counters.outdatedComponentCount;

  if (coreOutdatedConfidently || confidentlyOutdated.length >= MAINTENANCE_URGENT_OUTDATED) {
    const reasons: RatingReason[] = [];
    if (coreOutdatedConfidently) reasons.push({ key: 'rating.maintenance.reason.coreOutdated' });
    if (confidentlyOutdated.length >= MAINTENANCE_URGENT_OUTDATED) {
      reasons.push({
        key: 'rating.maintenance.reason.manyOutdated',
        params: { count: confidentlyOutdated.length },
      });
    }
    return { category: 'maintenance', level: 'urgent', reasons };
  }

  if (outdatedCount >= 1) {
    return {
      category: 'maintenance',
      level: 'attention',
      reasons: [
        { key: 'rating.maintenance.reason.someOutdated', params: { count: outdatedCount } },
      ],
    };
  }

  if (coverageOf(context, MAINTENANCE_COVERAGE_ENRICHMENT) === 'not_assessed') {
    return {
      category: 'maintenance',
      level: 'not_assessed',
      reasons: [{ key: 'rating.maintenance.reason.notAssessed' }],
    };
  }

  return {
    category: 'maintenance',
    level: 'clear',
    reasons: [{ key: 'rating.maintenance.reason.clear' }],
  };
}

const INFRASTRUCTURE_REASON_KEYS: Record<string, string> = {
  'finding.tls.invalidCertificate.recommendation':
    'rating.infrastructure.reason.invalidCertificate',
  'finding.tls.outdatedProtocol.recommendation': 'rating.infrastructure.reason.outdatedProtocol',
  'finding.infrastructure.noHttps.recommendation': 'rating.infrastructure.reason.noHttps',
};

function infrastructureReason(finding: Finding): RatingReason {
  return {
    key:
      INFRASTRUCTURE_REASON_KEYS[finding.recommendationKey] ??
      'rating.infrastructure.reason.finding',
    params: { severity: finding.severity },
  };
}

/**
 * No `urgent` tier exists for this category (unlike security/maintenance) —
 * TLS/HTTPS problems are real but capped at `attention` by design.
 * `not_assessed` only when the effective (post-redirect) URL is `https:`
 * but tls-scanner produced no successful result (errored, or the run never
 * reached it) — a genuinely HTTP-only site already has its own concrete
 * "no HTTPS" Finding (finding-engine.ts's `deriveHttpsFindings`), so that
 * case is handled by the findings-first branch below, not this fallback.
 */
export function rateInfrastructure(
  context: AuditContext,
  findings: readonly Finding[],
): CategoryRating {
  const infraFindings = findings.filter((finding) => finding.category === 'infrastructure');

  if (infraFindings.length > 0) {
    return {
      category: 'infrastructure',
      level: 'attention',
      reasons: infraFindings.map(infrastructureReason),
    };
  }

  const isHttps = new URL(effectiveUrl(context)).protocol === 'https:';
  const tlsAssessed =
    !isHttps ||
    getScannerData<TlsProbeResult>(context.getScannerResults(), 'tls-scanner') !== undefined;

  if (!tlsAssessed) {
    return {
      category: 'infrastructure',
      level: 'not_assessed',
      reasons: [{ key: 'rating.infrastructure.reason.notAssessed' }],
    };
  }

  return {
    category: 'infrastructure',
    level: 'clear',
    reasons: [{ key: 'rating.infrastructure.reason.clear' }],
  };
}

const LEVEL_RANK: Record<RatingLevel, number> = {
  not_assessed: -1,
  clear: 0,
  attention: 1,
  urgent: 2,
};

/** Worst of the three, ignoring `not_assessed` categories — only `not_assessed` itself when all three are. */
export function rateOverall(categories: readonly CategoryRating[]): {
  level: RatingLevel;
  reasons: RatingReason[];
} {
  const assessed = categories.filter((c) => c.level !== 'not_assessed');
  if (assessed.length === 0) {
    return { level: 'not_assessed', reasons: [{ key: 'rating.overall.reason.notAssessed' }] };
  }

  const worst = assessed.reduce((worstSoFar, current) =>
    LEVEL_RANK[current.level] > LEVEL_RANK[worstSoFar.level] ? current : worstSoFar,
  );
  return { level: worst.level, reasons: worst.reasons };
}

export function calculateRatings(
  context: AuditContext,
  findings: readonly Finding[],
  counters: ReportCounters,
): RatingSummary {
  const categories = [
    rateSecurity(context, findings),
    rateMaintenance(context, findings, counters),
    rateInfrastructure(context, findings),
  ];

  return { categories, overall: rateOverall(categories) };
}
