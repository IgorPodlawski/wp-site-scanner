import { z } from 'zod';

export const envSchema = z.object({
  WPSCAN_API_TOKEN: z.string().optional(),
  PAGESPEED_API_KEY: z.string().optional(),

  AUDIT_CONTACT_URL: z.string().url().default('https://example.com/about-this-scan'),
  AUDIT_USER_AGENT: z.string().default('wp-audit/0.1 (+see AUDIT_CONTACT_URL)'),

  LOG_LEVEL: z.enum(['debug', 'info', 'warn', 'error']).default('info'),

  CACHE_DIR: z.string().default('./data/cache'),
  // Phase 4 only — accepted now so .env files written against the full spec
  // don't fail validation, but nothing reads it before SQLite is introduced.
  DATABASE_PATH: z.string().optional(),

  HTTP_TIMEOUT_MS: z.coerce.number().int().positive().default(10_000),
  MAX_REDIRECTS: z.coerce.number().int().nonnegative().default(5),
  MAX_RESPONSE_BYTES: z.coerce.number().int().positive().default(10_485_760),

  BATCH_CONCURRENCY: z.coerce.number().int().positive().default(4),
  PER_HOST_DELAY_MS: z.coerce.number().int().nonnegative().default(1000),
});

export type EnvConfig = z.infer<typeof envSchema>;
