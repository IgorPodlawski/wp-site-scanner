import type { AuditResult } from '../core/types/index.js';
import type { Locale } from '../i18n/types.js';
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
    reports.html = renderHtml(result, lang);
  }
  if (formats.includes('pdf') && reports.html) {
    reports.pdf = await renderPdf(reports.html);
  }

  return reports;
}
