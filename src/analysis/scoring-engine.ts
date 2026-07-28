import type { MeasuredScoreSummary } from '../core/types/index.js';
import type { PageSpeedResult } from '../integrations/enrichment-types.js';

/**
 * The only numbers left on a 0-100 scale are ones backed by a real,
 * deterministic external measurement — currently just Performance via
 * Google Lighthouse/PageSpeed. This returns that number directly, never a
 * synthetic deduction: a *good* PageSpeed score used to produce no Finding
 * at all (nothing to flag), which meant the actual measured number was
 * invisible everywhere in a clean run — this makes it visible regardless of
 * Finding-worthiness, the same reason report-counters.ts/rating-engine.ts
 * read coverage independently of Findings.
 *
 * Security/Maintenance/Infrastructure/Overall are qualitative instead (see
 * rating-engine.ts) — a 0-100 number for those invented false precision for
 * what is fundamentally a judgment call. SEO isn't modeled here either:
 * there is no real Lighthouse SEO category wired up yet, so there is no
 * number to show — the report renders a static "not assessed" row for it
 * instead of faking one.
 */
export function calculateMeasuredScores(
  pageSpeedResult: PageSpeedResult | undefined,
): MeasuredScoreSummary {
  if (!pageSpeedResult) return { categories: [] };

  return {
    categories: [{ category: 'performance', value: pageSpeedResult.performanceScore }],
  };
}
