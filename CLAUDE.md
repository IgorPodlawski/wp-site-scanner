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
minAuthorization: 'prospect' | 'audit'
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
  name: string
  minAuthorization: 'prospect' | 'audit'
  supports(context: AuditContext): boolean
  run(context: AuditContext): Promise<ScannerResult>
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
10. Check public endpoints *(audit only)*
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

**WordPress.org** — latest version, last update, active installs, compatibility.

**WPScan** — known vulnerabilities / CVEs / fixed versions. Use the **WPScan vulnerability database API only** (a data lookup). Do **not** invoke the WPScan CLI scanner — its active enumeration contradicts the "NOT a pentest tool" constraint. The free WPScan API tier is rate-limited (~100 requests/day); treat this as a real design constraint for batch runs and lean on the cache. Requires `WPSCAN_API_TOKEN`.

**PageSpeed** — mobile performance, Core Web Vitals. Requires `PAGESPEED_API_KEY`.

Every external API must: use a timeout, retry at most once, use the cache, and never crash the audit. A failed enrichment degrades the run to `partial`, it does not abort it.

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

Contains: target, authorization mode, consent artifact, HTTP response, HTML, detected plugins, detected theme, endpoint results, API enrichments, findings, scores, scanner results.

**AuditResult** — the immutable persisted output. Do not mix the two.

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

**Confidence caps severity (hard rule):**
- `inferred` → severity may not exceed `medium`
- `corroborated` → may not exceed `high`
- only `confirmed` may be `critical`

This is the mechanical implementation of "false positives are worse than misses." It is not optional.

**CVE assertion rule:** a vulnerability is asserted as *applicable* only when the component version is `confirmed` **and** falls inside the affected range (`affected_version < fixed_in`). Otherwise emit it as **"potentially affected"** with reduced severity. Never present a CVE as confirmed off an `inferred` version.

---

# Scoring

Categories: Security, Maintenance, Performance, SEO, Infrastructure, Overall.

Start each at 100. Reduce per finding as a function of `severity × confidence` (lower confidence → smaller deduction). No invented mathematical complexity — scoring only prioritizes. Keep the deduction table explicit and in one place (`analysis/scoring`), so it is reviewable and testable.

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

> TODO (agent to define exact command wiring / arg parser). Reference shape:

```bash
wp-audit audit https://example.com                       # prospect mode, standard profile
wp-audit audit https://example.com --profile quick
wp-audit audit https://example.com --profile deep
wp-audit audit https://example.com --i-have-authorization  # unlocks audit mode
wp-audit audit https://example.com --lang pl
wp-audit batch leads.csv                                  # prospect by default
wp-audit batch leads.csv --i-have-authorization           # requires per-row consent column
wp-audit history example.com
```

---

# Commands (fill in once tooling is chosen)

> TODO — agent fills these in after scaffolding. Leave blank until decided.

- package manager: <!-- npm / pnpm / yarn -->
- install: <!-- e.g. pnpm install -->
- build: <!-- -->
- typecheck: <!-- -->
- lint: <!-- -->
- test (all): <!-- -->
- test (single file): <!-- -->
- run CLI in dev: <!-- -->

---

# Testing

- Scanners are tested against **recorded HTTP fixtures** (`tests/fixtures/`), never against live sites — deterministic, CI-safe, and the main defense against false-positive regressions. Use nock or msw (agent decides).
- Cover: version-detection confidence rules, confidence-caps-severity, the CVE applicability rule, SSRF rejection, redirect validation, non-WordPress graceful exit, and mode enforcement (a `audit`-only scanner must not run in `prospect`).
- Every finding-producing rule needs at least one positive and one negative fixture.

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

**Phase 1** — CLI, basic scanners, WordPress.org enrichment, JSON + HTML, EN/PL scaffolding, prospect/audit mode enforcement.

**Phase 2** — WPScan API, PageSpeed, cache, scoring.

**Phase 3** — batch mode (with consent handling), history, compare, deep profile.

**Phase 4** — SQLite, PDF export, AI-generated sales email.

---

# Philosophy

Optimize for correctness, maintainability, modularity, evidence, developer experience.

Not for maximum findings, sensational reports, or aggressive scanning.

Every reported issue should help start a meaningful, honest conversation with a potential client — and every network request should be one we could defend if the target's owner asked why we made it.
