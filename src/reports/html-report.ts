import { readFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import type {
  AuditResult,
  Finding,
  FindingSeverity,
  Insight,
  ScoreSummary,
} from '../core/types/index.js';
import type { Locale, LocaleMessages } from '../i18n/types.js';
import { loadLocale } from '../i18n/loader.js';
import { interpolate } from '../i18n/translate.js';
import type { DetectedPlugin } from '../scanners/plugin-scanner.js';
import type { DetectedTheme } from '../scanners/theme-scanner.js';

const TEMPLATE_PATH = path.join(path.dirname(fileURLToPath(import.meta.url)), 'templates/report.html');

const SEVERITY_RANK: Record<FindingSeverity, number> = {
  critical: 4,
  high: 3,
  medium: 2,
  low: 1,
  info: 0,
};

function escapeHtml(value: string): string {
  return value
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

type Translate = (key: string, params?: Record<string, string | number>) => string;

/** Translates then escapes in one step — every piece of text this module inserts into the HTML goes through here. */
function text(t: Translate, key: string, params?: Record<string, string | number>): string {
  return escapeHtml(t(key, params));
}

function renderSummarySection(result: AuditResult, t: Translate): string {
  const rows: Array<[string, string]> = [
    [text(t, 'report.summary.target'), escapeHtml(result.target.domain)],
    [text(t, 'report.summary.mode'), text(t, `report.mode.${result.authorizationMode}`)],
    [text(t, 'report.summary.profile'), escapeHtml(result.profile)],
    [text(t, 'report.summary.status'), text(t, `report.status.${result.status}`)],
    [text(t, 'report.summary.wordpress'), text(t, result.isWordPress ? 'report.value.yes' : 'report.value.no')],
    [text(t, 'report.summary.startedAt'), escapeHtml(result.startedAt)],
    [text(t, 'report.summary.finishedAt'), escapeHtml(result.finishedAt)],
  ];

  const rowsHtml = rows.map(([label, value]) => `<tr><th>${label}</th><td>${value}</td></tr>`).join('');
  return `<h2>${text(t, 'report.summary.title')}</h2><table>${rowsHtml}</table>`;
}

function renderScoresSection(scores: ScoreSummary | undefined, t: Translate): string {
  if (!scores) return '';

  const rows = [
    ...scores.categories.map(
      (c) => `<tr><th>${text(t, `score.category.${c.category}`)}</th><td>${c.value}</td></tr>`,
    ),
    `<tr><th>${text(t, 'score.category.overall')}</th><td>${scores.overall}</td></tr>`,
  ].join('');

  return `<h2>${text(t, 'report.section.scores')}</h2><table>${rows}</table>`;
}

function renderInsightsSection(insights: readonly Insight[], t: Translate): string {
  if (insights.length === 0) return '';

  const items = insights
    .map((insight) => `<div class="insight">${text(t, insight.messageKey, insight.messageParams)}</div>`)
    .join('');

  return `<h2>${text(t, 'report.section.insights')}</h2>${items}`;
}

function renderFindingsSection(findings: readonly Finding[], t: Translate): string {
  if (findings.length === 0) {
    return `<h2>${text(t, 'report.section.findings')}</h2><p class="empty-state">${text(t, 'report.findings.empty')}</p>`;
  }

  const sorted = [...findings].sort((a, b) => SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity]);
  const cards = sorted
    .map((finding) => {
      const evidence = finding.evidence
        .map((e) => `<p class="finding-evidence">${text(t, e.descriptionKey, e.params)}</p>`)
        .join('');
      const meta = `${text(t, `score.category.${finding.category}`)} · ${text(t, `report.severity.${finding.severity}`)} · ${text(t, `report.confidence.${finding.confidence}`)}`;
      const badgeClass = `severity-${finding.severity}`;

      return (
        `<div class="finding">` +
        `<span class="badge ${badgeClass}">${text(t, `report.severity.${finding.severity}`)}</span> ` +
        `<span class="finding-meta">${meta}</span>` +
        evidence +
        `<p class="finding-recommendation">${text(t, finding.recommendationKey, finding.recommendationParams)}</p>` +
        `</div>`
      );
    })
    .join('');

  return `<h2>${text(t, 'report.section.findings')}</h2>${cards}`;
}

function findScannerData<T>(result: AuditResult, scannerName: string): T | undefined {
  const scanner = result.scannerResults.find((r) => r.scannerName === scannerName && r.status === 'ok');
  return scanner?.data as T | undefined;
}

function renderComponentLine(t: Translate, slug: string, version: string | undefined): string {
  const versionLabel = version ?? t('report.component.versionUnknown');
  return `<li>${text(t, 'report.component.entry', { slug, version: versionLabel })}</li>`;
}

function renderPluginsSection(result: AuditResult, t: Translate): string {
  const plugins = findScannerData<{ plugins: DetectedPlugin[] }>(result, 'plugin-scanner')?.plugins;
  if (!plugins || plugins.length === 0) {
    return `<h2>${text(t, 'report.section.plugins')}</h2><p class="empty-state">${text(t, 'report.plugins.empty')}</p>`;
  }

  const items = plugins.map((p) => renderComponentLine(t, p.slug, p.version?.value)).join('');
  return `<h2>${text(t, 'report.section.plugins')}</h2><ul>${items}</ul>`;
}

function renderThemeSection(result: AuditResult, t: Translate): string {
  const themes = findScannerData<{ themes: DetectedTheme[] }>(result, 'theme-scanner')?.themes;
  if (!themes || themes.length === 0) {
    return `<h2>${text(t, 'report.section.theme')}</h2><p class="empty-state">${text(t, 'report.theme.empty')}</p>`;
  }

  const items = themes.map((th) => renderComponentLine(t, th.slug, th.version?.value)).join('');
  return `<h2>${text(t, 'report.section.theme')}</h2><ul>${items}</ul>`;
}

function renderLimitationsSection(limitations: readonly string[], t: Translate): string {
  if (limitations.length === 0) return '';

  const items = limitations.map((l) => `<li>${escapeHtml(l)}</li>`).join('');
  return `<h2>${text(t, 'report.section.limitations')}</h2><ul>${items}</ul>`;
}

function renderConsentSection(result: AuditResult, t: Translate): string {
  const consent = result.consentArtifact;
  if (!consent) return '';

  const rows: Array<[string, string]> = [
    [text(t, 'report.consent.domain'), escapeHtml(consent.targetDomain)],
    [text(t, 'report.consent.timestamp'), escapeHtml(consent.timestamp)],
    ...(consent.operatorNote ? [[text(t, 'report.consent.note'), escapeHtml(consent.operatorNote)] as [string, string]] : []),
  ];
  const rowsHtml = rows.map(([label, value]) => `<tr><th>${label}</th><td>${value}</td></tr>`).join('');

  return `<h2>${text(t, 'report.consent.title')}</h2><table>${rowsHtml}</table>`;
}

function renderDisclaimer(result: AuditResult, t: Translate): string {
  if (result.consentArtifact) {
    return text(t, 'report.disclaimer.consent', {
      timestamp: result.consentArtifact.timestamp,
      domain: result.consentArtifact.targetDomain,
    });
  }
  return text(t, 'report.disclaimer');
}

function buildTranslator(messages: LocaleMessages): Translate {
  return (key, params) => interpolate(messages[key] ?? key, params);
}

/**
 * Renders src/reports/templates/report.html for a given locale — the exact
 * same template PDF export (Phase 4) will render, so section-building stays
 * here rather than in a one-off HTML string. Loads the locale independently
 * of the CLI's global `setLocale()` so report generation never depends on
 * (or fights over) ambient locale state.
 */
export async function renderHtml(result: AuditResult, lang: Locale): Promise<string> {
  const messages = await loadLocale(lang);
  const t = buildTranslator(messages);
  const template = await readFile(TEMPLATE_PATH, 'utf-8');

  const replacements: Record<string, string> = {
    LANG: lang,
    REPORT_TITLE: text(t, 'report.summary.title'),
    SUMMARY_SECTION: renderSummarySection(result, t),
    SCORES_SECTION: renderScoresSection(result.scores, t),
    INSIGHTS_SECTION: renderInsightsSection(result.insights, t),
    FINDINGS_SECTION: renderFindingsSection(result.findings, t),
    PLUGINS_SECTION: renderPluginsSection(result, t),
    THEME_SECTION: renderThemeSection(result, t),
    LIMITATIONS_SECTION: renderLimitationsSection(result.limitations, t),
    CONSENT_SECTION: renderConsentSection(result, t),
    DISCLAIMER: renderDisclaimer(result, t),
  };

  return Object.entries(replacements).reduce(
    (html, [token, value]) => html.replaceAll(`{{${token}}}`, value),
    template,
  );
}
