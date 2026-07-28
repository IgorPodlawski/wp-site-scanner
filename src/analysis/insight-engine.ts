import type { Finding, Insight } from '../core/types/index.js';

interface InsightRule {
  messageKey: string;
  matches: (finding: Finding) => boolean;
  /** Defaults to `{ count: matched.length }` — only overridden when a rule needs a different shape (see insight.knownVulnerabilities). */
  params?: (matched: Finding[]) => Record<string, string | number>;
}

function totalVulnerabilities(matched: readonly Finding[]): number {
  return matched.reduce(
    (sum, finding) => sum + (finding.component?.vulnerabilities.length ?? 0),
    0,
  );
}

/**
 * Synthesizes evidence-based, client-facing takeaways from Findings —
 * fulfils CLAUDE.md's "Sales Insight Engine" spec, deliberately renamed and
 * kept out of any client-visible label/key, since these reports get shared
 * directly with the client. Evidence-based only, never exaggerated: each
 * rule below only ever groups Findings that were actually raised (never
 * asserts anything beyond them), and every Insight carries the exact
 * findingIds it's built on.
 *
 * Missing security headers / info-disclosure headers deliberately have no
 * rule here — they're hygiene recommendations (see html-report.ts's
 * "Quick wins" section), not risk findings worth a headline insight.
 */
const INSIGHT_RULES: InsightRule[] = [
  {
    // "22 vulnerabilities across 8 components", never a single ambiguous
    // number — {{count}} used to mean "components", which silently
    // undercounted the actual number of known vulnerabilities.
    messageKey: 'insight.knownVulnerabilities',
    matches: (finding) => (finding.component?.vulnerabilities.length ?? 0) > 0,
    params: (matched) => ({
      componentCount: matched.length,
      vulnCount: totalVulnerabilities(matched),
    }),
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
    // Covers both TLS findings and the "no HTTPS at all" finding — both are
    // 'infrastructure' category (see finding-engine.ts).
    messageKey: 'insight.tlsConfiguration',
    matches: (finding) => finding.category === 'infrastructure',
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
      messageParams: rule.params ? rule.params(matched) : { count: matched.length },
    });
  }

  return insights;
}
