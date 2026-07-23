/**
 * A client-facing, evidence-based takeaway synthesized from one or more
 * Findings — never free text, so every rendered sentence goes through i18n
 * like everything else user-facing. `findingIds` is what keeps this
 * evidence-based: an Insight may only reference Findings that were actually
 * raised, never assert something beyond what was observed.
 */
export interface Insight {
  findingIds: string[];
  messageKey: string;
  messageParams?: Record<string, string | number>;
}
