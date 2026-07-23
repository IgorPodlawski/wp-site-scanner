export type ScoreCategory =
  'security' | 'maintenance' | 'performance' | 'seo' | 'infrastructure' | 'overall';

export interface CategoryScore {
  category: ScoreCategory;
  /** Starts at 100, reduced by deductions. */
  value: number;
  deductions: Array<{ findingId: string; amount: number }>;
}

export interface ScoreSummary {
  categories: CategoryScore[];
  overall: number;
}
