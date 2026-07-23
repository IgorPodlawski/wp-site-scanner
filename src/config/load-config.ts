import dotenv from 'dotenv';
import { envSchema } from './env-schema.js';
import type { AppConfig } from './types.js';

/**
 * Loads and validates configuration from environment variables. Missing
 * WPSCAN_API_TOKEN / PAGESPEED_API_KEY are valid states (those enrichments
 * are simply disabled) — this must never throw for that reason. It throws
 * only when a *provided* value is malformed (e.g. a non-numeric timeout).
 */
export function loadConfig(env: NodeJS.ProcessEnv = process.env): AppConfig {
  dotenv.config();

  const parsed = envSchema.safeParse(env);
  if (!parsed.success) {
    const issues = parsed.error.issues
      .map((issue) => `  - ${issue.path.join('.') || '(root)'}: ${issue.message}`)
      .join('\n');
    throw new Error(`Invalid environment configuration:\n${issues}`);
  }

  return {
    ...parsed.data,
    wpscanEnabled: parsed.data.WPSCAN_API_TOKEN !== undefined,
    pagespeedEnabled: parsed.data.PAGESPEED_API_KEY !== undefined,
  };
}
