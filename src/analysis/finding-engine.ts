import { randomUUID } from 'node:crypto';
import type { AuditContext, Finding, ScannerResult } from '../core/types/index.js';
import { createFinding } from '../core/types/finding.js';
import type { HeaderScannerData, SecurityHeaderName } from '../scanners/header-scanner.js';
import type { TlsProbeResult } from '../core/http/tls-probe.js';
import type { EndpointScannerData } from '../scanners/endpoint-scanner.js';

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

/**
 * Interprets raw scanner observations into Findings. Never emit raw scanner
 * output directly — every Finding goes through core/types/finding.ts's
 * createFinding(), which mechanically enforces confidence-caps-severity.
 * Only covers the observations that need no external enrichment (headers,
 * TLS, audit-only endpoints) — outdated-component findings need the
 * WordPress.org "latest version" comparison, which is separate enrichment
 * work not wired in yet.
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

  return findings;
}
