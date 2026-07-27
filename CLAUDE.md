# CLAUDE.md

# WP Audit CLI

## Mission

Build a high-quality internal CLI tool that performs **black-box WordPress quality assessments**.

The tool supports sales conversations by identifying real maintenance, security and quality issues visible from the public Internet. As a product it exports a PDF report (English or Polish) with organized results.

It is **NOT**:

- a pentesting framework
- an exploit framework
- a vulnerability scanner that performs attacks
- a brute-force tool

It only analyses publicly available information.

---

# Two operating axes (read this before anything else)

The tool has **two independent axes**. Do not collapse them into one flag. This distinction is the single most important design constraint in the project — it is a legal and reputational boundary, not a preference.

## Axis 1 — Authorization mode (hard boundary)

- `prospect` (**default**): analyse a target **without prior consent**. Only do what a normal browser rendering the page would do. **No path guessing of any kind.**
- `audit`: full analysis **on targets we own or have written permission to test**. Gated behind a consent artifact (see below).

## Axis 2 — Intensity profile (how thorough, within what the mode allows)

- `quick`, `standard`, `deep`

The profile is **always bounded by the mode**. `--profile deep` in `prospect` mode does more thorough Layer-1 work and third-party enrichment — it still never probes guessed paths. Only `audit` mode unlocks Layer 2 and Layer 3.

**`--profile deep` is implemented** for `PluginScanner`/`ThemeScanner` (both modes get it; the two halves are independently gated):

- **prospect + deep:** also fetches the CSS/JS assets the homepage already references (`core/http/asset-links.ts`) and scans those bodies too — still Layer 1, never a guessed path, since every URL fetched was already linked from the page.
- **audit + deep only:** Layer 3 dictionary enumeration — probes a small, curated, individually-verified list of well-known plugin/theme slugs (~50 plugins, ~14 themes, hardcoded in each scanner) via `readme.txt`/`style.css`, for anything Layers 1–2 missed because its slug never appears anywhere on the homepage. Discovered components are merged into the _same_ `plugins`/`themes` array Layer 1 populates, so they automatically get WordPress.org outdated-checks and WPScan CVE lookups for free — no separate wiring needed. Verified live against wordpress.org: this is what actually found `akismet`/`jetpack`/`bbpress`/etc., none of which are referenced anywhere in that homepage's HTML.
- `quick`/`standard` currently behave identically to each other (no scanner distinguishes them) — only `deep` unlocks anything. Every other scanner ignores `profile` entirely.
- Any slug added to either dictionary should be verified against the live `api.wordpress.org/plugins|themes/info/` endpoint first — a typo'd slug just silently never matches anything, and this is deliberately a small curated list, not a wordlist (see the Mission's "NOT a brute-force tool").

## What each mode may touch

**PROSPECT (Layer 1 only)**

- fetch homepage + assets already referenced by the HTML
- `generator` meta, plugin/theme slugs from `/wp-content/...` paths, `?ver=` params
- HTTP headers, security headers, TLS
- third-party enrichment: WordPress.org (version metadata), PageSpeed (Google fetches the target, not us)
- **must not**: probe `readme.txt` per plugin, `/wp-json/wp/v2/users`, config backups, `.git`/`.env`, directory listing, or run any dictionary enumeration

**AUDIT (Layers 1–3, requires consent artifact)**

- everything in Layer 1, plus:
- Layer 2 targeted probes: plugin `readme.txt` (`Stable tag`), theme `style.css` header, `/readme.html`, `/wp-json/wp/v2/users`, `xmlrpc.php`, directory listing, config-backup paths
- Layer 3 dictionary enumeration of plugins/themes (only at `--profile deep`)
- full WPScan CVE enrichment

## Consent artifact (audit mode gate)

Before an `audit` run starts, the orchestrator **must** require and persist:

- target domain
- explicit consent confirmation (flag `--i-have-authorization` **or** a `consent` field in the batch row)
- timestamp
- optional operator note

This is stored inside `AuditResult` and printed in the report. Keep it lightweight — the point is an auditable trail that the run was authorized. If the artifact is missing, the audit run **fails fast** with a clear message. Never silently downgrade audit→prospect.

## Scanner-level enforcement

Every scanner declares the lowest authorization it requires:

```ts
minAuthorization: 'prospect' | 'audit';
```

The orchestrator filters scanners by the active mode **before** running them. Enforcement lives in the orchestrator, not in each scanner — a scanner must be impossible to run outside its allowed mode even if called by mistake.

## Batch

`wp-audit batch leads.csv` defaults to `prospect`. Running a batch in `audit` mode requires a `consent` column populated per row; rows without it are skipped and reported as skipped, not run.

---

# Primary goals

- detect WordPress (and exit gracefully if the target is not WordPress)
- detect WordPress core version when possible
- detect plugins
- detect theme
- detect outdated components
- detect known vulnerabilities via external APIs (CVE database lookup, **not** active exploitation)
- detect common configuration issues
- generate a clear HTML report
- generate machine-readable JSON
- generate a PDF report (EN/PL)
- generate sales-oriented insights backed by evidence

Accuracy over quantity. Three meaningful findings beat fifty weak ones. **False positives are worse than missed findings.**

---

# Tech Stack

- Node.js 22+
- TypeScript
- Zod for external-input validation
- Pino for logging
- Storage: **JSON files in Phase 1–3**, **SQLite added in Phase 4** (see Roadmap). Do not introduce SQLite before Phase 4.
- PDF: rendered from the HTML report (engine TBD — likely Playwright or a HTML→PDF lib; decide in Phase 4, keep the report template PDF-friendly from the start)
- i18n: EN/PL from day one (see i18n section)

---

# Project structure

```text
src/
    cli/
    core/
    scanners/
    integrations/
    analysis/
    reports/
    storage/
    config/
    i18n/
    utils/

data/
reports/
locales/
tests/
    fixtures/
```

---

# Architecture

Modular pipeline. Business logic must never depend on the CLI. The CLI is only an entry point.

```
CLI
    ↓
AuditOrchestrator   (enforces authorization mode + consent gate)
    ↓
Scanners            (filtered by minAuthorization)
    ↓
External API enrichment
    ↓
Finding Engine
    ↓
Scoring Engine
    ↓
Sales Insight Engine
    ↓
Report Generator    (JSON, HTML, PDF)
```

---

# Audit Orchestrator

Coordinates the audit. Does NOT perform technical analysis.

Responsibilities:

- validate target (incl. SSRF checks)
- resolve authorization mode and enforce the consent gate for `audit`
- create AuditContext
- filter scanners by `minAuthorization`
- execute independent scanners in parallel
- collect results
- short-circuit if the target is not WordPress
- invoke enrichment
- generate findings, scores, sales insights
- generate reports and persist output

---

# Scanner architecture

One responsibility per scanner.

```ts
interface Scanner {
  name: string;
  minAuthorization: 'prospect' | 'audit';
  supports(context: AuditContext): boolean;
  run(context: AuditContext): Promise<ScannerResult>;
}
```

Scanners never call each other. Communication happens only through AuditContext. Never mix fetching with interpretation inside a scanner — a scanner produces raw observations; findings are derived later.

---

# Audit pipeline

1. Validate target
2. SSRF protection
3. Resolve DNS
4. Resolve authorization mode + consent gate
5. Fetch homepage
6. Detect WordPress — **if not WordPress, finalize as `completed` with a single informational finding and skip WP-specific scanners**
7. Detect core version
8. Detect plugins
9. Detect theme
10. Check public endpoints _(audit only)_
11. Check security headers
12. Check TLS
13. Enrich via external APIs
14. Generate findings
15. Calculate scores
16. Generate sales insights
17. Save JSON (+ SQLite from Phase 4)
18. Generate HTML
19. Generate PDF

---

# MVP scanners

Required:

- HTTP Scanner — `prospect`
- WordPress Detector — `prospect`
- Core Version Scanner — `prospect`
- Plugin Scanner — `prospect` (Layer-1 slug detection); Layer-2 version probing is `audit`
- Theme Scanner — `prospect` (Layer-1); Layer-2 `style.css` probing is `audit`
- Endpoint Scanner — `audit`
- Header Scanner — `prospect`
- TLS Scanner — `prospect`

Future:

- Performance Scanner (PageSpeed) — `prospect`
- SEO Scanner — `prospect`
- Technology Scanner — `prospect`

---

# External APIs

**WordPress.org** — implemented in `src/integrations/wordpress-org-client.ts`, verified against the live API. Notes for anyone touching this again:

- Plugin/theme info is `GET https://api.wordpress.org/plugins/info/1.2/` (not `1.0` — the `1.0/{slug}.json` shortcut endpoint omits `active_installs` entirely). Requires the query params `action=plugin_information` (or `theme_information`), `request[slug]=<slug>`, `request[fields][active_installs]=1`.
- "Not found" comes back as **HTTP 200** with `{"error": "Plugin not found."}` (or `{"error": "Theme not found"}`) — not a 404. Client treats this as `ok(undefined)`, not a failure.
- Core version status is a _separate_, simpler endpoint: `GET https://api.wordpress.org/core/stable-check/1.0/` returns a flat `{ "<version>": "latest" | "outdated" | "insecure", ... }` map covering essentially every released version. `insecure` is wordpress.org itself confirming known vulnerabilities for that exact version — this is a stronger signal than the plugin/theme "compare against latest" approach and is used directly (see Findings section).

**WPScan** — implemented in `src/integrations/wpscan-client.ts`, verified against the live API (a real `WPSCAN_API_TOKEN` was available during development — see the git history around the WPScan integration commit for the verification transcript). Use the **WPScan vulnerability database API only** (a data lookup). Do **not** invoke the WPScan CLI scanner — its active enumeration contradicts the "NOT a pentest tool" constraint. Notes:

- `GET https://wpscan.com/api/v3/plugins/{slug}` / `.../themes/{slug}`, header `Authorization: Token token=<WPSCAN_API_TOKEN>`.
- Unknown slug → **HTTP 404** with `{"status":"...", "is_error":true}` (opposite convention from WordPress.org's plugin API!) — treated as "no known vulnerabilities," not a failure.
- Response is keyed by the slug: `{"<slug>": {"vulnerabilities": [...], ...}}`. Each vulnerability's `id` is a UUID **string**, not a number. `fixed_in` may be `null`/absent (no patch released yet — treat as still-affected). `references` is an object (`{url: [...], cve: [...]}`), not a flat array — the client flattens it to `["CVE-...", ...urls]` to match the internal `WpscanVulnerability` shape. `vuln_type` and `description` are wired through as-is (`vulnType`/`description`); `cvss`, when populated, is expected to be `{score, vector, rating}` per WPScan's public docs, but **this exact populated shape is not verified live** — every real vulnerability sampled during development had `cvss: null` — so `cvssScore` is extracted defensively (`z.unknown()` + a manual numeric check) and degrades to "no CVSS" rather than throwing if the assumption is wrong. Re-verify against a populated example if this is touched again.
- Free tier is rate-limited (~100 requests/day); this is a real constraint for batch runs — lean on the 7-day cache.
- **Audit-mode only** (see "What each mode may touch" above) — enforced in `AuditOrchestrator`, not in the client itself. The client's own `wpscanEnabled` check only covers "is a token configured," so don't rely on it alone for the authorization-mode boundary.
- **WordPress core vulnerabilities** — `WpscanClient.getCoreVulnerabilities(version)`, verified live against the real API. Core is looked up differently from plugins/themes: `GET /wordpresses/{version-with-dots-stripped}` (e.g. `"6.5.4"` → `"654"`), and — unlike the plugin/theme endpoints — **the response is keyed by the canonical dotted version string, not by the numeric key that was sent**; the client reads `Object.values(parsed)[0]` rather than indexing by the request key. Same 404-means-"no known vulnerabilities" and wire shape otherwise. Wired into `finding-engine.ts` by passing a single synthetic `{kind: 'core', slug: 'wordpress-core', version}` through the _same_ `assembleComponentFinding` used for plugins/themes (see "Component findings" above) — reused rather than duplicated. The `finding.component.core.*`/`finding.componentVulnerability.core.*` i18n keys deliberately don't reference `{{slug}}` (unlike the plugin/theme equivalents), since "wordpress-core" is an internal dict key, never user-facing text.
- **CVE ids in evidence text**: when WPScan's `references` includes one or more `CVE-...` entries, `finding-engine.ts`'s `formatVulnerabilityTitle()` appends them to the displayed vulnerability title in parentheses (e.g. `"... Stored XSS (CVE-2024-6386)"`) — applies to plugin, theme, and core vulnerability findings alike, since they all flow through `assembleComponentFinding`. Not every WPScan entry has an assigned CVE; when none is present the title is shown unchanged.

**PageSpeed** — implemented in `src/integrations/pagespeed-client.ts`, verified against the live API (a real `PAGESPEED_API_KEY` was available during development). Notes:

- `GET https://www.googleapis.com/pagespeedonline/v5/runPagespeed?url=<url>&key=<key>&strategy=mobile&category=performance`. Google actually loads and audits the page itself (matches CLAUDE.md's "Google fetches the target, not us" — prospect-safe).
- **This call can legitimately take 10-20+ seconds** (Lighthouse runs a real page load remotely) — the client uses its own 30s timeout, not the shared `HTTP_TIMEOUT_MS` used for our own fast lookups against other APIs. Don't reuse the shared timeout for this client if you touch it again.
- `lighthouseResult.categories.performance.score` is a lab measurement, 0-1 scale (multiply by 100). The three _official_ Core Web Vitals (LCP, CLS, INP) come from a **separate, optional** field: `loadingExperience.metrics` — real-user CrUX field data, entirely absent when a URL doesn't have enough real-user traffic for Google to report on. `CUMULATIVE_LAYOUT_SHIFT_SCORE.percentile` needs dividing by 100 to get the actual CLS score (e.g. percentile `15` → CLS `0.15`); LCP/INP percentiles are already in ms.
- Any error (bad URL, Lighthouse couldn't load the page, rate limit) comes back as **HTTP 400+** with a structured `{"error": {...}}` body — always a genuine failure, there's no "not found"/"nothing to report" case analogous to the WordPress.org/WPScan clients.
- One finding per audit based on the overall score (`performance.poor`/`performance.needsImprovement` message keys, thresholds at 50/90 matching Google's own bucketing) — not one finding per Core Web Vital; the individual LCP/CLS/INP numbers go into `evidence[].raw` for the JSON report, not separate findings.

Every external API must: use a timeout, retry at most once, use the cache, and never crash the audit. A failed enrichment degrades the run to `partial`, it does not abort it. Implemented as: each client returns a `Result<T, Error>` (`src/utils/result.ts`) — `ok(value)` including `ok(undefined)`/`ok([])` for "legitimately nothing here" vs `err(error)` for "the API call itself failed" — so the orchestrator can tell "not found" apart from "couldn't check" and only degrade to `partial` for the latter.

---

# Cache

Mandatory. Provide a `--no-cache` / force-clear option.

TTL:

- WordPress.org: 24h
- WPScan: 7d
- PageSpeed: 12h

Key format: `provider:type:identifier:version`

Phase 1–3: cache as JSON files under `CACHE_DIR`. Phase 4: may move into SQLite.

---

# AuditContext vs AuditResult

**AuditContext** — mutable runtime state passed through the pipeline. It grows only through **controlled, append-style writes** by the orchestrator between stages (e.g. `context.addScannerResult(...)`). No scanner mutates another scanner's data; no free-form mutation. Treat each field as write-once per producing stage.

Contains: target, authorization mode, consent artifact, HTTP response, HTML, detected plugins, detected theme, endpoint results, API enrichments, findings, scores, insights, scanner results.

**AuditResult** — the immutable persisted output. Do not mix the two.

Implementation note: `findings` and `scores`/`insights` are handled inconsistently today — `AuditContext.addFinding()`/`getFindings()` exist on the interface but `AuditOrchestrator.run()` never actually calls them (it builds the findings array locally from `generateFindings(context)` and puts it straight into `AuditResult`); `setScoreSummary()`/`setInsights()`, by contrast, are actually called. Not a deliberate design choice — just an inconsistency nobody has fixed yet. If you touch this, prefer making `addFinding` actually used (or removing it) over adding a third pattern.

---

# Version detection

Every detected version includes:

- `value`
- `source` (e.g. `generator-meta`, `asset-query-string`, `plugin-readme`, `theme-stylesheet`)
- `confidence` (`inferred` | `corroborated` | `confirmed`)

Rules:

- `?ver=1.2.3` on an asset is `inferred` at best (cache-busters lie).
- A single source → max `corroborated`.
- `confirmed` requires **two independent sources** agreeing (e.g. `readme` + `stylesheet`).
- **A candidate version must match `major.minor[.patch]` (require the dot) before it's accepted from anywhere — generator meta, asset `?ver=`, a plugin's `Stable tag:`, or a theme's `Version:` header.** Caching/optimization plugins (seen live: WP Rocket) rewrite the `?ver=` of _any_ asset — including the small allowlist of WordPress-authored files `CoreVersionScanner` otherwise trusts (`wp-emoji-release.min.js`, `wp-embed.min.js`, `dashicons.min.css`) — to their own cache-busting value: a bare Unix timestamp (`?ver=1774442679`, no dot → now correctly rejected) or a content hash (`?ver=85d537c6`, which a digits-only pattern used to partial-match as the bogus version `"85"`). Being on the file allowlist is necessary but not sufficient; the captured value must still look like a version. This shape check is centralized as `WP_VERSION_SHAPE` in `analysis/version-confidence.ts` and shared by `CoreVersionScanner` and `ComponentScanner` (the base behind `PluginScanner`/`ThemeScanner`) — fix it once here, not per scanner.

---

# Findings

Findings are interpreted problems, never raw scanner output.

Every finding contains:

- `category`
- `severity` — `info | low | medium | high | critical`
- `confidence` — `inferred | corroborated | confirmed`
- `sourceLayer` — `1 | 2 | 3 | third-party`
- `businessImpact` — `none | weak | medium | strong`
- `recommendation`
- `evidence` — the concrete observation(s) supporting it
- `component` (optional) — present only on a merged WordPress core/plugin/theme finding: `{ kind, slug, isOutdated, vulnerabilitySeverities }` (see "Component findings" below)

**Severity comes from the vulnerability's own data — confidence never adjusts it.** There is no confidence-caps-severity mechanism (removed; a prior version of this rule capped a `critical` CVE down to `medium` purely because the installed version was only `inferred`, which mixed up two unrelated questions). Resolution order (`analysis/vulnerability-severity.ts`'s `resolveVulnerabilitySeverity`, backed by `analysis/cvss-severity.ts`'s fixed CVSS table):

1. CVSS base score, mapped via the fixed table: `9.0–10.0 → critical`, `7.0–8.9 → high`, `4.0–6.9 → medium`, `0.1–3.9 → low`, `0 → info`.
2. A WPScan-provided severity string, if present (not currently exposed by the real WPScan v3 API — verified live — but the fallback chain is built for it regardless).
3. `medium`, if neither is available. Never invented beyond this.

Confidence still matters, just for two different things: it scales the deduction in scoring (see below) and it selects report wording — `confirmed` (version confirmed **and** the vulnerability is applicable) → "has a known vulnerability"; anything less → "may be affected by a known vulnerability." Never mark a version `confirmed` off a bare `?ver=` alone (unchanged rule, enforced in `analysis/version-confidence.ts`).

**Applicability (independent of confidence):** a vulnerability is included for a component only when the detected version falls inside the affected range (`installed < fixed_in`, or no fix published yet) — `analysis/finding-engine.ts`'s `isAffectedByVulnerability`. This gate decides inclusion and the confirmed/potential wording; it never touches severity.

**Component findings — one per component, not one per vulnerability.** `analysis/finding-engine.ts`'s `assembleComponentFinding` merges a component's outdated-status and its deduplicated (`analysis/vulnerability-dedup.ts`), applicable vulnerabilities into a single Finding — never a separate "outdated" finding plus a separate finding per vulnerability for the same underlying problem. The finding's `severity` is the max across its applicable vulnerabilities' resolved severities; with zero vulnerabilities but an outdated version, it's a fixed `medium` `maintenance` finding (unchanged from before). A component flagged only by wordpress.org's coarse "insecure" status (no itemized WPScan data for it) is `maintenance`/`medium` like any other outdated-only component — the distinction still shows up in the evidence text, just not in severity, since there's no vulnerability-level data to derive a severity from.

---

# Scoring

Categories: Security, Maintenance, Performance, SEO, Infrastructure, Overall. Each starts at 100.

`analysis/scoring-engine.ts` keeps two small, explicit tables (not a single 2D lookup, since confidence and severity now play genuinely different roles):

- `BASE_PENALTY` by severity: `critical 30, high 18, medium 8, low 3, info 0`.
- `CONFIDENCE_WEIGHT` by confidence: `confirmed 1.0, corroborated 0.8, inferred 0.5`.

A plain (non-component) finding deducts `round(BASE_PENALTY[severity] * CONFIDENCE_WEIGHT[confidence])`.

A **component finding** with ≥1 vulnerability aggregates instead of using its own single severity directly: sort each applicable vulnerability's base penalty descending, take 100% of the worst plus 25% of each of the rest, then apply the component's confidence weight to that sum — finally capped at a hard **30**, regardless of how many vulnerabilities the component has. Because this cap applies identically wherever the deduction is added (the finding's own category, and `overall`), no single component can ever reduce any one score by more than 30 — this is what guarantees `overall` can't be driven below 70 by one component alone; it isn't a separate clamp.

`overall` is not an average of the categories — every finding (component or plain) reduces it regardless of category, so it reflects total risk while the per-category breakdown shows where it concentrates. Every category and `overall` are clamped at 0.

**Report counters** (`analysis/finding-engine.ts`'s `calculateReportCounters`, attached to `AuditResult.counters`): `componentsWithVulnerabilities`, `uniqueVulnerabilityCount` (deduplicated — CVE → WPScan id → normalized title — across every component, not just within one, so the same CVE affecting two components still counts once), `outdatedComponentCount`, `findingsBySeverity`. Not routed through `AuditContext` — `getScoreSummary()`/`getInsights()` are already write-only/never-read there (see the AuditContext vs AuditResult section), so counters go straight onto `AuditResult` instead of extending that dead pattern.

---

# i18n (EN / PL)

Locale-aware from the start — retrofitting later means rewriting the finding model.

- Findings, recommendations and sales insights are authored as **message keys + interpolation params**, never hardcoded strings.
- Translations live in `locales/{en,pl}.json`.
- Locale is selected per run (`--lang en|pl`, default `en`).
- JSON output stays language-neutral (keys + params); HTML and PDF render in the chosen locale.

---

# Sales Insight Engine

Evidence-based only. Never exaggerate.

Bad: "Your website is insecure."
Good: "Several publicly visible components appear to be outdated, which may increase maintenance and security risk."

Every insight references the finding(s) it is built on.

**Naming note:** implemented as `Insight` / `generateInsights()` in `src/analysis/insight-engine.ts` — deliberately renamed away from "sales" anywhere in code, types, JSON output, or i18n keys (`insight.*`, not `report.salesInsights.*`), since these reports are shared directly with the client. This doc keeps the section title for continuity with the concept it specifies; the codebase intentionally does not use the word.

Current rules (`INSIGHT_RULES` in `insight-engine.ts`) group Findings by theme rather than emitting one insight per finding: known vulnerabilities, priority (critical/high severity), outdated components, missing security headers, info disclosure, TLS configuration, exposed endpoints. A single Finding can legitimately surface under more than one rule (e.g. a critical exposed-endpoint finding appears in both the priority bucket and the exposed-endpoints bucket) — that's intentional, not a dedup bug.

---

# Reports

Generate: JSON, HTML, PDF.

HTML/PDF contain: summary, scores, findings, detected plugins, detected theme, recommendations, sales insights, limitations.

Always include a disclaimer that the audit is based only on publicly available information, plus (for `audit` runs) the consent artifact. Keep the HTML template PDF-friendly so PDF is a render of the same template, not a separate layout.

---

# Security & polite-scanning

**SSRF protection.** Reject: localhost, private IPv4, private IPv6, link-local, cloud metadata endpoints. Validate every redirect against the same rules (a redirect must not lead into a blocked range).

Limits (config defaults, overridable via env):

- timeout: 10s
- max redirects: 5
- max response: 10 MB

**User-Agent.** Identifiable, with a contact URL from `AUDIT_CONTACT_URL`, so a scanned host can recognize and reach us. Overridable via `AUDIT_USER_AGENT`.

**Batch throttling.** Enforce both a per-host delay and a global concurrency cap (`BATCH_CONCURRENCY`, `PER_HOST_DELAY_MS`). Never hammer a prospect's server.

**`robots.txt`:** not treated as a gate. Prospect mode is a single browser-equivalent fetch (homepage + referenced assets), not crawling, so `Disallow` rules do not apply to what we do. Politeness is enforced instead via browser-equivalent request volume, throttling, and an identifiable User-Agent. If prospect scope ever grows beyond a single page (or for batch), honor `Crawl-delay` as a politeness signal.

Never perform: brute force, exploits, login attempts, destructive actions.

**TLS certificate validation is deliberately disabled on the shared `UndiciHttpClient`** (`rejectUnauthorized: false` in `core/http/http-client.ts`'s `createPinnedDispatcher`) — this is not an oversight. An expired/self-signed/mismatched certificate must not make every scanner's fetch fail outright; `TlsScanner` (which connects the same way, on purpose) is the one that inspects and reports the cert problem as a proper finding. Without this, the tool couldn't audit exactly the sites most likely to have a real, sales-relevant TLS problem — confirmed against a real client site whose cert had expired months earlier (full audit failed with "unreachable target" until this was fixed). This is safe specifically because we never send secrets over these connections and do our own independent, authoritative TLS validation via `TlsScanner` — do not "fix" this back to strict validation.

**A redirect (or oversized) response body must be discarded via a helper that first attaches a no-op `error` listener** (`destroyQuietly()` in `http-client.ts`), never a bare `.destroy()`. undici's `BodyReadable` can emit an async `'error'` event (`UND_ERR_ABORTED`) after being destroyed unconsumed, and Node crashes the _entire process_ on an error event with zero listeners — this isn't caught by any try/catch, since it isn't thrown synchronously where the destroy happens. Found via a real `--profile deep` audit crashing mid-run with an unhandled `RequestAbortedError`.

---

# Environment variables

Create a `.env` with the following (names are fixed in code; values are yours to provide):

```
# External APIs
WPSCAN_API_TOKEN=
PAGESPEED_API_KEY=

# Identity / politeness
AUDIT_CONTACT_URL=
AUDIT_USER_AGENT=        # optional; overrides the default UA string

# Logging
LOG_LEVEL=info           # info | warn | error | debug

# Storage / cache
CACHE_DIR=./data/cache
DATABASE_PATH=./data/wp-audit.sqlite   # Phase 4 only

# HTTP limits (optional overrides of config defaults)
HTTP_TIMEOUT_MS=10000
MAX_REDIRECTS=5
MAX_RESPONSE_BYTES=10485760

# Batch tuning
BATCH_CONCURRENCY=4
PER_HOST_DELAY_MS=1000
```

Validate all of these with Zod at startup. Missing `WPSCAN_API_TOKEN` / `PAGESPEED_API_KEY` must not crash the tool — it disables that enrichment and downgrades affected runs to `partial`.

---

# Error handling

Audit status: `completed | partial | failed`.

One failing scanner must never terminate the audit — it is recorded and the run continues (→ `partial`). `failed` is reserved for target-level failures (invalid target, SSRF rejection, unreachable host, missing consent in audit mode).

---

# Logging

Pino. Levels: info, warn, error, debug. Default CLI shows concise progress; `LOG_LEVEL=debug` for detail.

---

# CLI

Wired with Commander (`src/cli/program.ts`, `src/cli/commands/*.ts`).

**`audit` — implemented, end-to-end.**

```bash
wp-audit audit https://example.com                       # prospect mode, standard profile
wp-audit audit https://example.com --profile quick
wp-audit audit https://example.com --profile deep
wp-audit audit https://example.com --i-have-authorization  # unlocks audit mode (sets consent: {confirmed: true, source: 'cli-flag'})
wp-audit audit https://example.com --lang pl
wp-audit audit https://example.com --no-cache
```

Runs the full pipeline (scanners → enrichment → findings → scoring → insights) and writes both `data/audits/<domain>/<timestamp>.json` and `reports/<domain>/<timestamp>.html`, printing both paths.

**`batch` and `history` — still stubs.** Both commands exist and parse args, but their handlers just print a "not implemented" message (Phase 3). Do not assume batch throttling (`BATCH_CONCURRENCY`/`PER_HOST_DELAY_MS`) or history/compare work yet — the env vars are validated and available, but nothing reads them.

```bash
wp-audit batch leads.csv                                  # prospect by default — not yet implemented
wp-audit batch leads.csv --i-have-authorization           # requires per-row consent column — not yet implemented
wp-audit history example.com                              # not yet implemented
```

---

# Commands

- package manager: pnpm
- install: `pnpm install`
- build: `pnpm build` (compiles to `dist/` and copies `src/reports/templates/` into `dist/reports/templates/` — `tsc` doesn't copy non-`.ts` assets, so the report template needs an explicit copy step)
- typecheck: `pnpm typecheck`
- lint: `pnpm lint`
- format: `pnpm format` / check-only: `pnpm format:check`
- test (all): `pnpm test`
- test (watch): `pnpm test:watch`
- test (single file): `pnpm test <path-or-pattern>` (e.g. `pnpm test tests/unit/finding-engine.test.ts`)
- run CLI in dev: `pnpm dev -- audit https://example.com`
- run CLI built: `pnpm build && node dist/cli/index.js audit https://example.com`

---

# Testing

- Scanners and integration clients are tested by **dependency-injecting fake `HttpClient`/`CacheStore` objects** (plain objects implementing those interfaces), never against live sites — deterministic, CI-safe, and the main defense against false-positive regressions. This is the pattern actually in use across the whole test suite; follow it for new scanners/clients rather than introducing an HTTP-interceptor library. (Decided-against: `nock` is still in `devDependencies` from the initial scaffold but is unused — `tests/unit/http-client.test.ts` is the one exception, using undici's own `MockAgent` since it's testing the low-level HTTP client itself, not something built on top of it.)
- Cover: version-detection confidence rules, confidence-caps-severity, the CVE applicability rule, SSRF rejection, redirect validation, non-WordPress graceful exit, and mode enforcement (a `audit`-only scanner must not run in `prospect`).
- Every finding-producing rule needs at least one positive and one negative fixture.
- **Before trusting an assumed external API response shape, verify it against the real API** (with a real token/response if at all available) before writing the client's Zod schema — fixture tests alone will happily pass against your own incorrect assumption of the wire format. This caught two real bugs during development: WordPress.org's plugin-info endpoint silently omits `active_installs` unless requested via `request[fields][active_installs]=1` (the `1.0/{slug}.json` shortcut doesn't support this at all — use `1.2/` with query params), and a finding whose recommendation text needed a `{{param}}` that the finding-engine rule never actually passed (only visible once the HTML report was rendered and read, not from the unit tests). If a live API/token isn't available, say so explicitly rather than presenting an unverified integration as equivalent to a verified one.
- `tests/support/test-context.ts` holds `buildTestContext()`/`buildHttpResponse()`/`TEST_HTTP_OPTIONS` — the `AuditContext`/`HttpResponse`/`HttpClientOptions` construction that used to be copy-pasted per scanner test file. Use it for new scanner tests instead of redefining a local `createContext()`; only fall back to a bespoke local helper if a test's setup genuinely doesn't fit the shared shape.

---

# Engineering principles

- Small modules, one responsibility per scanner.
- Never mix: fetching / interpretation / scoring / reporting.
- Prefer composition over inheritance.
- AuditContext grows via controlled writes; no free-form mutation, no global state, no hidden side effects.
- Explicit typing. Avoid `any`. Validate external input with Zod.
- Readability over cleverness.

---

# Development workflow

1. Create/extend domain model if needed.
2. Implement scanner (set `minAuthorization`).
3. Add unit tests with fixtures.
4. Register scanner in the orchestrator.
5. Add findings (with confidence/severity rules).
6. Update scoring table if needed.
7. Add i18n keys for any new user-facing text.
8. Update reports.
9. Verify CLI.

---

# Definition of Done

Implemented, typed, Zod-validated where external input enters, tested (incl. a negative case), logged, i18n-keyed, documented, integrated into the pipeline, included in reports, and gracefully handling partial failures — and, for anything touching the network, respecting the authorization mode.

---

# Roadmap

Status as of the last update to this doc — keep this section current; it's the fastest way for anyone (human or agent) to know what's real vs planned without reading every source file.

**Phase 1** — CLI, basic scanners, WordPress.org enrichment, JSON + HTML, EN/PL scaffolding, prospect/audit mode enforcement. **✅ Done.** All 8 MVP scanners implemented and registered; orchestrator runs the real pipeline (scanners → WordPress.org enrichment → findings → scoring → insights → JSON + HTML persisted); `--i-have-authorization` actually works end-to-end (this was broken until recently — it set the mode but never supplied the consent object, so every real audit-mode CLI run failed immediately).

**Phase 2** — WPScan API, PageSpeed, cache, scoring. **✅ Done.** WPScan CVE enrichment: audit-mode-gated, verified against the live API. PageSpeed: prospect-safe, verified against the live API, feeds real findings into the `performance` score category (previously always 100). Cache (`FileCacheStore`, `provider:type:identifier:version` keys): done. Scoring (`analysis/scoring-engine.ts`, explicit deduction table): done.

**Phase 3** — batch mode (with consent handling), history, compare, deep profile. **Deep profile: done** (see Axis 2 above — `PluginScanner`/`ThemeScanner` asset-scanning at prospect+deep, Layer 3 dictionary enumeration at audit+deep, verified live). **Batch mode, history, compare: not started.** `wp-audit batch`/`wp-audit history` are registered commands that just print "not implemented."

**Phase 4** — SQLite, PDF export, AI-generated sales email. **Not started.** `pdf-report.ts` is an intentional stub (own docstring says Phase 4); the HTML template it will render is already built and print-friendly, so PDF should be "render the same template," not a new layout, once an engine is chosen.

---

# Philosophy

Optimize for correctness, maintainability, modularity, evidence, developer experience.

Not for maximum findings, sensational reports, or aggressive scanning.

Every reported issue should help start a meaningful, honest conversation with a potential client — and every network request should be one we could defend if the target's owner asked why we made it.
