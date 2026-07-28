/**
 * Qualitative levels for Security/Maintenance/Infrastructure/Overall —
 * replaces the old 0-100 point score for these categories (see
 * analysis/rating-engine.ts). `not_assessed` is deliberately distinct from
 * `clear`: it means the relevant check never ran or its data source was
 * entirely unavailable this run, never "we checked and it's fine".
 */
export type RatingLevel = 'clear' | 'attention' | 'urgent' | 'not_assessed';

export type RatedCategory = 'security' | 'maintenance' | 'infrastructure';

/** A concrete fact that contributed to a level, always an i18n key + params — never a raw string, same convention as FindingEvidence. */
export interface RatingReason {
  key: string;
  params?: Record<string, string | number>;
}

export interface CategoryRating {
  category: RatedCategory;
  level: RatingLevel;
  reasons: RatingReason[];
}

/**
 * `overall` is the worst of the three category levels (urgent > attention >
 * clear), ignoring any category that is `not_assessed` — it only becomes
 * `not_assessed` itself when all three are. See rating-engine.ts's
 * `rateOverall`.
 */
export interface RatingSummary {
  categories: CategoryRating[];
  overall: { level: RatingLevel; reasons: RatingReason[] };
}
