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

export const wordPressOrgThemeInfoSchema = z.object({
  slug: z.string(),
  version: z.string(),
  lastUpdated: z.string(),
  activeInstalls: z.number().int().nonnegative(),
});
export type WordPressOrgThemeInfo = z.infer<typeof wordPressOrgThemeInfoSchema>;

// wordpress.org/core/stable-check/1.0/ — a flat map of every released core
// version to its current status. 'insecure' means WordPress.org itself
// flags that version as having known vulnerabilities.
export const coreVersionStatusSchema = z.enum(['latest', 'outdated', 'insecure']);
export type CoreVersionStatus = z.infer<typeof coreVersionStatusSchema>;
export const coreStableVersionsSchema = z.record(z.string(), coreVersionStatusSchema);
export type CoreStableVersions = z.infer<typeof coreStableVersionsSchema>;

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
