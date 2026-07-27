import type { Finding, Insight } from '../core/types/index.js';

/**
 * Synthesizes evidence-based, client-facing takeaways from Findings —
 * fulfils CLAUDE.md's "Sales Insight Engine" spec, deliberately renamed and
 * kept out of any client-visible label/key, since these reports get shared
 * directly with the client. Evidence-based only, never exaggerated: each
 * rule below only ever groups Findings that were actually raised (never
 * asserts anything beyond them), and every Insight carries the exact
 * findingIds it's built on.
 */
const INSIGHT_RULES: Array<{ messageKey: string; matches: (finding: Finding) => boolean }> = [
  {
    messageKey: 'insight.knownVulnerabilities',
    matches: (finding) => (finding.component?.vulnerabilitySeverities.length ?? 0) > 0,
  },
  {
    messageKey: 'insight.priority',
    matches: (finding) => finding.severity === 'critical' || finding.severity === 'high',
  },
  {
    messageKey: 'insight.outdatedComponents',
    matches: (finding) => finding.component?.isOutdated === true,
  },
  {
    messageKey: 'insight.missingSecurityHeaders',
    matches: (finding) => finding.recommendationKey.startsWith('finding.header.missing'),
  },
  {
    messageKey: 'insight.infoDisclosure',
    matches: (finding) => finding.recommendationKey.startsWith('finding.header.infoDisclosure'),
  },
  {
    messageKey: 'insight.tlsConfiguration',
    matches: (finding) => finding.recommendationKey.startsWith('finding.tls.'),
  },
  {
    messageKey: 'insight.exposedEndpoints',
    matches: (finding) => finding.recommendationKey.startsWith('finding.endpoint.'),
  },
  {
    messageKey: 'insight.performance',
    matches: (finding) => finding.recommendationKey.startsWith('finding.performance.'),
  },
];

export function generateInsights(findings: readonly Finding[]): Insight[] {
  const insights: Insight[] = [];

  for (const rule of INSIGHT_RULES) {
    const matched = findings.filter(rule.matches);
    if (matched.length === 0) continue;

    insights.push({
      findingIds: matched.map((finding) => finding.id),
      messageKey: rule.messageKey,
      messageParams: { count: matched.length },
    });
  }

  return insights;
}
