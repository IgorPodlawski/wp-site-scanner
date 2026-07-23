import type {
  Finding,
  FindingConfidence,
  FindingSeverity,
  ScoreSummary,
} from '../core/types/index.js';
import { NotImplementedError } from '../core/errors.js';

/**
 * The single, reviewable place deduction amounts live (per CLAUDE.md:
 * "keep the deduction table explicit and in one place"). Values are
 * placeholders (0) — real numbers are Phase 2 scoring work, not
 * architecture. No invented mathematical complexity: scoring only
 * prioritizes, it does not need to be more elaborate than this table.
 */
export const DEDUCTION_TABLE: Record<FindingSeverity, Record<FindingConfidence, number>> = {
  info: { inferred: 0, corroborated: 0, confirmed: 0 },
  low: { inferred: 0, corroborated: 0, confirmed: 0 },
  medium: { inferred: 0, corroborated: 0, confirmed: 0 },
  high: { inferred: 0, corroborated: 0, confirmed: 0 },
  critical: { inferred: 0, corroborated: 0, confirmed: 0 },
};

export function calculateScores(_findings: readonly Finding[]): ScoreSummary {
  // TODO (Phase 2): start each category at 100, reduce via DEDUCTION_TABLE[severity][confidence].
  throw new NotImplementedError('calculateScores (Phase 2 feature work)');
}
