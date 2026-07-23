import { writeFile } from 'node:fs/promises';
import path from 'node:path';
import type { AuditResult } from '../core/types/index.js';
import type { Locale } from '../i18n/types.js';
import { ensureDir, htmlReportPathForResult } from '../storage/paths.js';
import { renderJson } from './json-report.js';
import { renderHtml } from './html-report.js';
import { renderPdf } from './pdf-report.js';

export type ReportFormat = 'json' | 'html' | 'pdf';

export interface GeneratedReports {
  json?: string;
  html?: string;
  pdf?: Buffer;
}

export async function generateReports(
  result: AuditResult,
  formats: readonly ReportFormat[],
  lang: Locale,
): Promise<GeneratedReports> {
  const reports: GeneratedReports = {};

  if (formats.includes('json')) {
    reports.json = renderJson(result);
  }
  if (formats.includes('html') || formats.includes('pdf')) {
    reports.html = await renderHtml(result, lang);
  }
  if (formats.includes('pdf') && reports.html) {
    reports.pdf = await renderPdf(reports.html);
  }

  return reports;
}

/** Minimal HTML persistence, mirroring storage/json-store.ts's saveAuditResult. */
export async function saveHtmlReport(result: AuditResult, html: string): Promise<string> {
  const filePath = htmlReportPathForResult(result);
  await ensureDir(path.dirname(filePath));
  await writeFile(filePath, html, 'utf-8');
  return filePath;
}
