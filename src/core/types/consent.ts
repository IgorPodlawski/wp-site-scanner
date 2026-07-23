/**
 * The audit-mode gate. `confirmed` is typed `true` (not `boolean`) so a
 * ConsentArtifact can only ever represent a granted consent — there is no
 * representable "consent: false" state to accidentally treat as authorized.
 */
export interface ConsentArtifact {
  targetDomain: string;
  confirmed: true;
  timestamp: string;
  operatorNote?: string;
  source: 'cli-flag' | 'batch-row';
}
