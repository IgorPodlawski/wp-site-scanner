import { readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';
import type { AuditResult } from '../core/types/index.js';
import { ensureDir, auditResultPathForResult, resolveAuditsDir } from './paths.js';

/** Minimal JSON persistence for AuditResult. History/query features are Phase 3 (`wp-audit history`). */
export async function saveAuditResult(result: AuditResult): Promise<string> {
  const filePath = auditResultPathForResult(result);
  await ensureDir(path.dirname(filePath));
  await writeFile(filePath, JSON.stringify(result, null, 2), 'utf-8');
  return filePath;
}

export async function loadAuditResult(filePath: string): Promise<AuditResult> {
  const raw = await readFile(filePath, 'utf-8');
  return JSON.parse(raw) as AuditResult;
}

export { resolveAuditsDir };
