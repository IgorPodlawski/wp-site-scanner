import type { AuthorizationMode, IntensityProfile } from '../types/authorization.js';
import type { Locale } from '../../i18n/types.js';

/** What the CLI (or a batch row) hands to the orchestrator — not yet validated/resolved. */
export interface AuditRequest {
  targetInput: string;
  requestedMode: AuthorizationMode;
  profile: IntensityProfile;
  lang: Locale;
  useCache: boolean;
  /** Present only when requestedMode is 'audit'. */
  consent?: {
    confirmed: boolean;
    operatorNote?: string;
    source: 'cli-flag' | 'batch-row';
  };
}
