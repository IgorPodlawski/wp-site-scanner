import { readFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import type {
  AuditResult,
  ComponentFindingInfo,
  Finding,
  FindingSeverity,
  Insight,
  ScoreSummary,
  VersionInfo,
} from '../core/types/index.js';
import { getScannerData } from '../core/types/scanner.js';
import { getScoreBand } from '../analysis/score-band.js';
import { resolveVulnerabilitySeverity } from '../analysis/vulnerability-severity.js';
import type { Locale, LocaleMessages } from '../i18n/types.js';
import { loadLocale } from '../i18n/loader.js';
import { interpolate } from '../i18n/translate.js';
import type { DetectedPlugin } from '../scanners/plugin-scanner.js';
import type { DetectedTheme } from '../scanners/theme-scanner.js';
import type { WpscanVulnerability } from '../integrations/enrichment-types.js';

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

/**
 * Always rendered, whether or not any finding ended up referencing the
 * version — a correctly-detected, up-to-date core version produces no
 * finding at all (nothing to flag), which previously meant it was invisible
 * everywhere in the report. Includes confidence inline so an `inferred`
 * value reads as exactly that, not as an unqualified fact.
 */
function renderCoreVersionValue(result: AuditResult, t: Translate): string {
  const version = getScannerData<{ version: VersionInfo | undefined }>(
    result.scannerResults,
    'core-version-scanner',
  )?.version;
  if (!version) {
    return text(t, 'report.summary.coreVersionUnknown');
  }
  return `${escapeHtml(version.value)} (${text(t, `report.confidence.${version.confidence}`)})`;
}

function renderTable(rows: ReadonlyArray<[string, string]>): string {
  const rowsHtml = rows.map(([label, value]) => `<tr><th>${label}</th><td>${value}</td></tr>`).join('');
  return `<table>${rowsHtml}</table>`;
}

function renderSummarySection(result: AuditResult, t: Translate): string {
  const rows: Array<[string, string]> = [
    [text(t, 'report.summary.target'), escapeHtml(result.target.domain)],
    [text(t, 'report.summary.mode'), text(t, `report.mode.${result.authorizationMode}`)],
    [text(t, 'report.summary.profile'), escapeHtml(result.profile)],
    [text(t, 'report.summary.status'), text(t, `report.status.${result.status}`)],
    [
      text(t, 'report.summary.wordpress'),
      text(t, result.isWordPress ? 'report.value.yes' : 'report.value.no'),
    ],
    ...(result.isWordPress
      ? ([[text(t, 'report.summary.coreVersion'), renderCoreVersionValue(result, t)]] as Array<
          [string, string]
        >)
      : []),
    ...(result.isWordPress && result.counters
      ? ([
          [
            text(t, 'report.summary.componentsWithVulnerabilities'),
            String(result.counters.componentsWithVulnerabilities),
          ],
          [
            text(t, 'report.summary.uniqueVulnerabilities'),
            String(result.counters.uniqueVulnerabilityCount),
          ],
          [
            text(t, 'report.summary.outdatedComponents'),
            String(result.counters.outdatedComponentCount),
          ],
        ] as Array<[string, string]>)
      : []),
    [text(t, 'report.summary.startedAt'), escapeHtml(result.startedAt)],
    [text(t, 'report.summary.finishedAt'), escapeHtml(result.finishedAt)],
  ];

  return `<h2>${text(t, 'report.summary.title')}</h2>${renderTable(rows)}`;
}

/** "72/100" plus a colored good/fair/poor badge, so a bare number never has to be read without context. */
function renderScoreValue(value: number, t: Translate): string {
  const band = getScoreBand(value);
  return `${value}/100 <span class="badge score-${band}">${text(t, `report.scoreBand.${band}`)}</span>`;
}

function renderScoresSection(scores: ScoreSummary | undefined, t: Translate): string {
  if (!scores) return '';

  const rows: Array<[string, string]> = [
    ...scores.categories.map(
      (c): [string, string] => [text(t, `score.category.${c.category}`), renderScoreValue(c.value, t)],
    ),
    [text(t, 'score.category.overall'), renderScoreValue(scores.overall, t)],
  ];

  return (
    `<h2>${text(t, 'report.section.scores')}</h2>` +
    `<p class="scores-scale-note">${text(t, 'report.scores.scaleNote')}</p>${renderTable(rows)}`
  );
}

function renderInsightsSection(insights: readonly Insight[], t: Translate): string {
  if (insights.length === 0) return '';

  const items = insights
    .map((insight) => `<div class="insight">${text(t, insight.messageKey, insight.messageParams)}</div>`)
    .join('');

  return `<h2>${text(t, 'report.section.insights')}</h2>${items}`;
}

const VULNERABILITY_EVIDENCE_PREFIX = 'finding.componentVulnerability.';

/** Turns an already-real WPScan reference into a clickable link (shown by hostname, not the full raw URL, to avoid ugly wrapping) — a bare "CVE-..." identifier is left as plain text, never turned into a synthesized lookup URL we didn't get from the data itself. */
function renderReference(ref: string): string {
  if (!/^https?:\/\//i.test(ref)) {
    return escapeHtml(ref);
  }
  let label = ref;
  try {
    label = new URL(ref).hostname;
  } catch {
    // Malformed URL from the API — fall back to showing it as-is rather than guessing.
  }
  return `<a href="${escapeHtml(ref)}" target="_blank" rel="noopener noreferrer">${escapeHtml(label)}</a>`;
}

/**
 * One visually self-contained card per vulnerability — previously each
 * vulnerability's sentence, meta line, description, and references ran
 * together as loose paragraphs with nothing separating one vulnerability
 * from the next, which made a component with several vulnerabilities read
 * as an undifferentiated wall of text. `sentence` is the already-
 * translated+escaped evidence text (just the title now — see the
 * shortened finding.componentVulnerability.* strings); everything else —
 * CVSS, severity, vulnerability type, fixed-in version, description,
 * references — comes straight from evidence.raw (the full
 * WpscanVulnerability), never re-derived or guessed. Severity is
 * recomputed here (not read off Finding.component, which only holds the
 * aggregate list) — cheap and pure, and avoids correlating two parallel
 * arrays by position.
 */
function renderVulnerabilityCard(
  t: Translate,
  sentence: string,
  vulnerability: WpscanVulnerability,
): string {
  const severity = resolveVulnerabilitySeverity(vulnerability);
  const metaParts = [
    `<span class="badge severity-${severity}">${text(t, `report.severity.${severity}`)}</span>`,
    vulnerability.cvssScore !== undefined
      ? `${text(t, 'report.vulnerability.cvss')}: ${escapeHtml(String(vulnerability.cvssScore))}`
      : undefined,
    vulnerability.vulnType
      ? `${text(t, 'report.vulnerability.type')}: ${escapeHtml(vulnerability.vulnType)}`
      : undefined,
    vulnerability.fixedIn
      ? `${text(t, 'report.vulnerability.fixedIn')}: ${escapeHtml(vulnerability.fixedIn)}`
      : undefined,
  ].filter((part): part is string => part !== undefined);

  const description = vulnerability.description
    ? `<p class="vulnerability-description">${escapeHtml(vulnerability.description)}</p>`
    : '';
  const references =
    vulnerability.references.length > 0
      ? `<p class="vulnerability-references">${text(t, 'report.vulnerability.references')}: ${vulnerability.references.map(renderReference).join(', ')}</p>`
      : '';

  return (
    `<div class="vulnerability-card">` +
    `<p class="vulnerability-title">${sentence}</p>` +
    `<p class="vulnerability-meta">${metaParts.join(' · ')}</p>` +
    description +
    references +
    `</div>`
  );
}

/** A component finding covers a whole plugin/theme/(WordPress core) — a heading up front says which one before diving into version info and vulnerabilities, instead of that identity only ever appearing buried in the first evidence sentence. */
function renderComponentHeading(t: Translate, component: ComponentFindingInfo): string {
  const kindLabel = text(t, `report.component.kind.${component.kind}`);
  const title = component.kind === 'core' ? kindLabel : `${kindLabel}: ${escapeHtml(component.slug)}`;
  return `<h3 class="finding-title">${title}</h3>`;
}

function renderFindingsSection(findings: readonly Finding[], t: Translate): string {
  if (findings.length === 0) {
    return `<h2>${text(t, 'report.section.findings')}</h2><p class="empty-state">${text(t, 'report.findings.empty')}</p>`;
  }

  const sorted = [...findings].sort((a, b) => SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity]);
  const cards = sorted
    .map((finding) => {
      const heading = finding.component ? renderComponentHeading(t, finding.component) : '';
      const evidence = finding.evidence
        .map((e) => {
          const sentence = text(t, e.descriptionKey, e.params);
          if (e.descriptionKey.startsWith(VULNERABILITY_EVIDENCE_PREFIX) && e.raw) {
            return renderVulnerabilityCard(t, sentence, e.raw as WpscanVulnerability);
          }
          return `<p class="finding-evidence">${sentence}</p>`;
        })
        .join('');
      const meta = `${text(t, `score.category.${finding.category}`)} · ${text(t, `report.severity.${finding.severity}`)} · ${text(t, `report.confidence.${finding.confidence}`)}`;
      const badgeClass = `severity-${finding.severity}`;

      return (
        `<div class="finding">` +
        `<span class="badge ${badgeClass}">${text(t, `report.severity.${finding.severity}`)}</span> ` +
        `<span class="finding-meta">${meta}</span>` +
        heading +
        evidence +
        `<p class="finding-recommendation">${text(t, finding.recommendationKey, finding.recommendationParams)}</p>` +
        `</div>`
      );
    })
    .join('');

  return `<h2>${text(t, 'report.section.findings')}</h2>${cards}`;
}

function renderComponentLine(t: Translate, slug: string, version: string | undefined): string {
  const versionLabel = version ?? t('report.component.versionUnknown');
  return `<li>${text(t, 'report.component.entry', { slug, version: versionLabel })}</li>`;
}

function renderPluginsSection(result: AuditResult, t: Translate): string {
  const plugins = getScannerData<{ plugins: DetectedPlugin[] }>(
    result.scannerResults,
    'plugin-scanner',
  )?.plugins;
  if (!plugins || plugins.length === 0) {
    return `<h2>${text(t, 'report.section.plugins')}</h2><p class="empty-state">${text(t, 'report.plugins.empty')}</p>`;
  }

  const items = plugins.map((p) => renderComponentLine(t, p.slug, p.version?.value)).join('');
  return `<h2>${text(t, 'report.section.plugins')}</h2><ul>${items}</ul>`;
}

function renderThemeSection(result: AuditResult, t: Translate): string {
  const themes = getScannerData<{ themes: DetectedTheme[] }>(
    result.scannerResults,
    'theme-scanner',
  )?.themes;
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
  return `<h2>${text(t, 'report.consent.title')}</h2>${renderTable(rows)}`;
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
