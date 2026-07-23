import { z } from 'zod';

// External-input boundaries — every third-party API response is validated
// with Zod before anything downstream trusts its shape.

export const wordPressOrgPluginInfoSchema = z.object({
  slug: z.string(),
  version: z.string(),
  lastUpdated: z.string(),
  activeInstalls: z.number().int().nonnegative(),
  tested: z.string().optional(),
});
export type WordPressOrgPluginInfo = z.infer<typeof wordPressOrgPluginInfoSchema>;

export const wpscanVulnerabilitySchema = z.object({
  id: z.string(),
  title: z.string(),
  fixedIn: z.string().optional(),
  cvssScore: z.number().optional(),
  references: z.array(z.string()).default([]),
});
export type WpscanVulnerability = z.infer<typeof wpscanVulnerabilitySchema>;

export const pageSpeedResultSchema = z.object({
  performanceScore: z.number().min(0).max(100),
  coreWebVitals: z.object({
    lcpMs: z.number().optional(),
    clsScore: z.number().optional(),
    inpMs: z.number().optional(),
  }),
});
export type PageSpeedResult = z.infer<typeof pageSpeedResultSchema>;
