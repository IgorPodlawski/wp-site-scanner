import type { EnvConfig } from './env-schema.js';

/**
 * Fully resolved application config. Extends the raw env schema with derived
 * flags so callers don't need to re-check `token !== undefined` everywhere.
 */
export interface AppConfig extends EnvConfig {
  wpscanEnabled: boolean;
  pagespeedEnabled: boolean;
}
