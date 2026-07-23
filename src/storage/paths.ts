import { mkdir } from 'node:fs/promises';
import path from 'node:path';
import type { AppConfig } from '../config/types.js';

const AUDITS_DIR = './data/audits';
const REPORTS_DIR = './reports';

export async function ensureDir(dirPath: string): Promise<string> {
  await mkdir(dirPath, { recursive: true });
  return dirPath;
}

export function resolveCacheDir(config: Pick<AppConfig, 'CACHE_DIR'>): string {
  return config.CACHE_DIR;
}

export function resolveAuditsDir(): string {
  return AUDITS_DIR;
}

export function resolveReportsDir(): string {
  return REPORTS_DIR;
}

export function auditResultPath(domain: string, timestamp: string): string {
  return path.join(resolveAuditsDir(), domain, `${timestamp}.json`);
}

/** Derives the on-disk path for a given result — the one place `finishedAt` becomes a filename-safe timestamp. */
export function auditResultPathForResult(result: {
  target: { domain: string };
  finishedAt: string;
}): string {
  return auditResultPath(result.target.domain, result.finishedAt.replace(/[:.]/g, '-'));
}
