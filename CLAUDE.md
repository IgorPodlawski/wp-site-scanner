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

This is stored inside `AuditResult` (and its JSON output) — **not** rendered in the HTML/PDF report, which is client-facing (deliberate product decision; see "Reports" below). Keep it lightweight — the point is an auditable trail that the run was authorized. If the artifact is missing, the audit run **fails fast** with a clear message. Never silently downgrade audit→prospect.

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
- generate findings, ratings, measured scores, sales insights
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
15. Calculate ratings (qualitative) and measured scores (numeric, Performance only)
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
- Free tier is rate-limited (~100 requests/day); this is a real constraint for batch runs — lean on the 7-day cache. A rate-limited request returns **HTTP 429** — verified live. `WpscanClient` trips an in-memory circuit breaker the first time it sees a 429 and short-circuits every subsequent plugin/theme/core lookup for the rest of that client's lifetime (one audit run) without making another HTTP call. Without this, a `--profile deep` audit-mode run probing dozens of dictionary slugs kept hitting the real API for every remaining one even after the daily quota was confirmed exhausted — and each of those hits also triggers a "Daily API Limit Reached" notification **email** from WPScan itself, so one exhausted run without the breaker meant dozens of emails, not one (found live).
  - **All WPScan calls are serialized through an internal queue, not just breaker-gated.** `enrichBySlug`/the orchestrator's own top-level enrichment step fire every plugin/theme (and core) lookup _concurrently_ via `Promise.all` — a plain boolean checked at call time isn't enough, because the entire first wave of concurrent calls each reads the flag as `false` (none of their responses have arrived yet) and each still fires its own real request. Verified live and with a dedicated regression test (`tests/unit/wpscan-client.test.ts`, "serializes concurrent calls fired via Promise.all"): without the queue, 10 concurrently-fired lookups against an exhausted quota produced 20 real requests (10 × the one retry each); with it, exactly 2 (only the first call in the queue ever reaches the network). This does mean WPScan lookups within one run are effectively one-at-a-time now, not parallel — an accepted tradeoff given the tiny daily quota.
  - The breaker is per-process/per-run only — it does not persist across separate CLI invocations, so a brand-new run still makes its own first attempt (and gets its own single 429/email) even on a day already known to be exhausted.
- **Audit-mode only** (see "What each mode may touch" above) — enforced in `AuditOrchestrator`, not in the client itself. The client's own `wpscanEnabled` check only covers "is a token configured," so don't rely on it alone for the authorization-mode boundary.
- **WordPress core vulnerabilities** — `WpscanClient.getCoreVulnerabilities(version)`, verified live against the real API. Core is looked up differently from plugins/themes: `GET /wordpresses/{version-with-dots-stripped}` (e.g. `"6.5.4"` → `"654"`), and — unlike the plugin/theme endpoints — **the response is keyed by the canonical dotted version string, not by the numeric key that was sent**; the client reads `Object.values(parsed)[0]` rather than indexing by the request key. Same 404-means-"no known vulnerabilities" and wire shape otherwise. Wired into `finding-engine.ts` by passing a single synthetic `{kind: 'core', slug: 'wordpress-core', version}` through the _same_ `assembleComponentFinding` used for plugins/themes (see "Component findings" above) — reused rather than duplicated. The `finding.component.core.*`/`finding.componentVulnerability.core.*` i18n keys deliberately don't reference `{{slug}}` (unlike the plugin/theme equivalents), since "wordpress-core" is an internal dict key, never user-facing text.
- **CVE ids in evidence text**: when WPScan's `references` includes one or more `CVE-...` entries, `finding-engine.ts`'s `formatVulnerabilityTitle()` appends them to the displayed vulnerability title in parentheses (e.g. `"... Stored XSS (CVE-2024-6386)"`) — applies to plugin, theme, and core vulnerability findings alike, since they all flow through `assembleComponentFinding`. Not every WPScan entry has an assigned CVE; when none is present the title is shown unchanged.

**PageSpeed** — implemented in `src/integrations/pagespeed-client.ts`, verified against the live API (a real `PAGESPEED_API_KEY` was available during development). Notes:

- `GET https://www.googleapis.com/pagespeedonline/v5/runPagespeed?url=<url>&key=<key>&strategy=mobile&category=performance`. Google actually loads and audits the page itself (matches CLAUDE.md's "Google fetches the target, not us" — prospect-safe).
- **This call can legitimately take 10-20+ seconds** (Lighthouse runs a real page load remotely) — the client uses its own 30s timeout, not the shared `HTTP_TIMEOUT_MS` used for our own fast lookups against other APIs. Don't reuse the shared timeout for this client if you touch it again.
- `lighthouseResult.categories.performance.score` is a lab measurement, 0-1 scale (multiply by 100). The three _official_ Core Web Vitals (LCP, CLS, INP) come from a **separate, optional** field: `loadingExperience.metrics` — real-user CrUX field data, entirely absent when a URL doesn't have enough real-user traffic for Google to report on. `CUMULATIVE_LAYOUT_SHIFT_SCORE.percentile` needs dividing by 100 to get the actual CLS score (e.g. percentile `15` → CLS `0.15`); LCP/INP percentiles are already in ms.
- Any error (bad URL, Lighthouse couldn't load the page, rate limit) comes back as **HTTP 400+** with a structured `{"error": {...}}` body — always a genuine failure, there's no "not found"/"nothing to report" case analogous to the WordPress.org/WPScan clients.
- One finding per audit based on the overall score (`performance.poor`/`performance.needsImprovement` message keys, thresholds at 50/90 matching Google's own bucketing) — not one finding per Core Web Vital; the individual LCP/CLS/INP numbers go into `evidence[].raw` for the JSON report, not separate findings.

**NVD + CISA KEV (PHP vulnerabilities)** — implemented in `src/integrations/php-vulnerability-client.ts`, verified against the live APIs. CERT.PL was investigated first (per a direct ask) and has no API/feed usable for this — NVD + CISA KEV were chosen instead, both free and public. Notes:

- PHP's own version is never probed for — it's read passively off the `X-Powered-By` response header the homepage fetch already received (`finding-engine.ts`'s `extractPhpVersion`), so this stays Layer 1/prospect-safe: no new network request, no guessed path. Many hardened hosts suppress this header entirely; when absent, the check simply has nothing to look up (same "degrade, don't fail" posture as every other enrichment gap).
- **NVD CVE API v2.0**: `GET https://services.nvd.nist.gov/rest/json/cves/2.0?cpeName=cpe:2.3:a:php:php:<version>:*:*:*:*:*:*:*&resultsPerPage=200`. Unauthenticated calls work; an optional `NVD_API_KEY` (sent as an `apiKey` header) only raises the rate ceiling — unlike `WPSCAN_API_TOKEN`/`PAGESPEED_API_KEY`, it never gates the feature on/off. Server-side filtering by `cpeName` is correct for _bounded_ ranges (`versionStartIncluding`/`versionStartExcluding`/`versionEndIncluding`/`versionEndExcluding`) — verified live.
- **Verified false-positive trap**: a bare, unbounded wildcard `cpeMatch` entry (`cpe:2.3:a:php:php:*:*:*:*:*:*:*:*`, no version-bound fields at all) matches _any_ queried version in NVD's virtual-match search, including genuinely unrelated/ancient CVEs (CVE-2007-3205 matched a live query for PHP 8.1.2). `findApplicableFixedIn` explicitly rejects an unbounded wildcard match rather than treating "no bounds" as "always applicable" — this is the same spirit as "no `?ver=` value is trusted at face value" above, just for a different source.
- **CISA KEV** (Catalog of Known Exploited Vulnerabilities): `GET https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json`, a flat public JSON list of CVE ids CISA has confirmed are being actively exploited. Cross-referenced against every NVD result found for the detected PHP version; sets `knownExploited: true` on the matching vulnerability. A KEV fetch failure degrades to `knownExploited: false` for everything, not a hard failure — matches the "never crash the audit" rule below.
- Cache TTLs: NVD results 24h (`PhpVulnerabilityClient.NVD_CACHE_TTL_MS`), KEV catalog 6h (`PhpVulnerabilityClient.KEV_CACHE_TTL_MS`) — the KEV catalog changes more often and is cheap (one flat file for all lookups, not per-version).
- **Reuses the existing component-finding pipeline rather than building a parallel one.** PHP is a fourth `ComponentFindingInfo.kind` (`'core' | 'plugin' | 'theme' | 'php'`); `PhpVulnerability` is a type alias for `WpscanVulnerability` (extended with an optional `knownExploited` field, `false`/absent for every WordPress core/plugin/theme vulnerability) so PHP CVEs flow through the exact same `assembleComponentFinding` as everything else — same severity resolution, same dedup, same i18n evidence-key pattern (`finding.component.php.*`, `finding.componentVulnerability.php.*`). `outdated` is always passed as `undefined` for PHP (there's no "latest PHP version" registry equivalent to wordpress.org), so a PHP finding is only ever produced when there's at least one applicable vulnerability.
- **Prospect-safe, not audit-gated** — deliberate product decision (see Axis 1 above): wired into `AuditOrchestrator.enrichPhpVulnerabilities`, which runs unconditionally alongside the other enrichment calls, gated only on whether a PHP version was actually detectable, never on authorization mode.
- **KEV overrides the confidence gate for Security's `urgent` threshold** (see Ratings below) — a deliberate, explicit exception, decided with the user rather than assumed: PHP version detection is realistically always single-source (`http-header`, capped at `inferred` — see Version detection), so it can never reach `confirmed` on its own, which would otherwise make a PHP vulnerability permanently unable to drive Security to `urgent` no matter how severe. `knownExploited: true` (CISA has _confirmed_ active exploitation) is treated as at least as strong a signal as our own `confirmed` version-detection bar.

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

Contains: target, authorization mode, consent artifact, HTTP response, HTML, detected plugins, detected theme, endpoint results, API enrichments, findings, insights, scanner results — plus two coverage flags (`SECURITY_COVERAGE_ENRICHMENT`, `MAINTENANCE_COVERAGE_ENRICHMENT`, written via the same `context.setEnrichment(...)` mechanism as every other cross-stage signal) that tell `rating-engine.ts` whether WPScan/wordpress.org actually ran this pass, independent of whether they found anything.

**AuditResult** — the immutable persisted output. Do not mix the two.

Implementation note: `findings` is handled inconsistently today — `AuditContext.addFinding()`/`getFindings()` exist on the interface but `AuditOrchestrator.run()` never actually calls them (it builds the findings array locally from `generateFindings(context)` and puts it straight into `AuditResult`); `setInsights()`, by contrast, is actually called. Not a deliberate design choice — just an inconsistency nobody has fixed yet. If you touch this, prefer making `addFinding` actually used (or removing it) over adding a third pattern. `ratings` and `measuredScores` follow the same pattern as `counters` — computed by the orchestrator and put straight onto `AuditResult`, never routed through `AuditContext` (there used to be a `setScoreSummary()`/`getScoreSummary()` pair on the interface for the old point-based scores; removed rather than extended to a third summary type, per the note above).

---

# Version detection

Every detected version includes:

- `value`
- `source` (e.g. `generator-meta`, `asset-query-string`, `plugin-readme`, `theme-stylesheet`)
- `confidence` (`inferred` | `corroborated` | `confirmed`)

Rules:

- `?ver=1.2.3` on an asset is `inferred` at best (cache-busters lie).
- A lone `http-header` source (e.g. PHP's version read off `X-Powered-By`, see External APIs' NVD/CISA KEV entry) is capped at `inferred` for the same reason — a page cache can serve a stale header from before a server-side PHP upgrade just as easily as a stale asset reference. `analysis/version-confidence.ts`'s `WEAK_SINGLE_SOURCES` set groups `asset-query-string` and `http-header` together under this same cap.
- A single source → max `corroborated` (except the weak sources above, capped at `inferred`).
- `confirmed` requires **two independent sources** agreeing (e.g. `readme` + `stylesheet`).
- **Two sources that genuinely disagree never average out to `corroborated` — the tie-break pick is capped at `inferred`.** `analysis/version-confidence.ts`'s `deriveVersionInfo` breaks a tie (each candidate value seen exactly once) toward whichever was listed first (`ComponentScanner` lists the probed `readme.txt`/`style.css` value before the asset `?ver=`, since a direct file probe is normally the more trustworthy of the two) — but found live: a real plugin's `readme.txt` "Stable tag" was itself stale (10.9.4) while the site's actual, live assets were already on 11.0.0 (confirmed via `wp-admin`) — the developer shipped a code update without bumping the readme. Calling the tie-break's pick `corroborated` when a second, independent signal actively contradicted it overstates confidence — `corroborated` should mean "nothing disagreed," not "we picked one of two conflicting guesses." A group that already has 2+ _agreeing_ sources keeps its normal confidence even if a lone third candidate also disagreed with it — real agreement between independent sources still counts.
- No `?ver=` value is trusted at face value even when it looks like a real version: a page cache can serve a stale asset reference from before the last core/plugin upgrade, or a plugin's own readme can lag behind its actual shipped code — either way, `inferred` confidence is the ceiling, which is exactly why `rateMaintenance`'s `urgent` threshold (see Ratings below) requires better than `inferred` before asserting "outdated" as a headline claim.
- **A candidate version must match `major.minor[.patch]` (require the dot) before it's accepted from anywhere — generator meta, asset `?ver=`, a plugin's `Stable tag:`, or a theme's `Version:` header.** Caching/optimization plugins (seen live: WP Rocket) rewrite the `?ver=` of _any_ asset — including the small allowlist of WordPress-authored files `CoreVersionScanner` otherwise trusts (`wp-emoji-release.min.js`, `wp-embed.min.js`, `dashicons.min.css`) — to their own cache-busting value: a bare Unix timestamp (`?ver=1774442679`, no dot → now correctly rejected) or a content hash (`?ver=85d537c6`, which a digits-only pattern used to partial-match as the bogus version `"85"`). Being on the file allowlist is necessary but not sufficient; the captured value must still look like a version. This shape check is centralized as `WP_VERSION_SHAPE` in `analysis/version-confidence.ts` and shared by `CoreVersionScanner` and `ComponentScanner` (the base behind `PluginScanner`/`ThemeScanner`) — fix it once here, not per scanner.
- **The shape check narrows false positives, it doesn't eliminate them: an `inferred`, single-source `?ver=` value can still look like a real version and be wrong** — found live on a real client site running WP Fastest Cache: the homepage's cached HTML still referenced `?ver=6.5.4` after the site had actually been upgraded to 7.0.3 (confirmed via `wp-admin`), because the page cache hadn't been purged since the upgrade. `CoreVersionScanner`/`ComponentScanner` have no way to distinguish "this cache-buster happens to be a real, current version" from "this cache-buster happens to look like a plausible but stale/wrong version" — both pass the shape check identically. This is a known, accepted limitation of black-box detection (see Mission: "only analyses publicly available information" — a stale public cache **is** what's publicly visible), not a parsing bug — but it means an `inferred`-confidence "outdated" claim carries real, demonstrated risk of being wrong and should be read with that in mind.
- **WordPress core lives under `/wp-content/` and `/wp-includes/` by default, but Bedrock (roots.io) and similar boilerplates rename the content directory to `/app/`** (same internal structure — `app/themes/`, `app/plugins/`, `app/mu-plugins/`, `app/uploads/`). `WordPressDetector` additionally checks for `/app/(themes|plugins|mu-plugins|uploads)/` and `/wp-json/` so a Bedrock site isn't misclassified as non-WordPress (found live: a real Bedrock+Sage client site matched none of the original four signals — no generator meta, no `wp-content`/`wp-includes`, no `api.w.org` link). `ComponentScanner` (the base behind `PluginScanner`/`ThemeScanner`) detects which content root is actually in use once per scan from real evidence already in the fetched body (`CONTENT_ROOTS = ['wp-content', 'app']`, tried in that order, defaulting to `wp-content` when the body gives no signal either way) and uses that root consistently for Layer-1 slug extraction, Layer-2 version probing, and Layer-3 dictionary enumeration — never guessed per request, and never doubles network requests once the root is known. `EndpointScanner`'s uploads-directory-listing check tries both `wp-content/uploads/` and `app/uploads/` directly (a single cheap probe either way, no root-detection needed there). `CoreVersionScanner` needed no change — its asset-`?ver=` patterns aren't anchored to the start of the path, so `/wp/wp-includes/...` (Bedrock also moves WordPress core itself under `wp/`) still matches as a substring.

---

# Findings

Findings are interpreted problems, never raw scanner output.

Every finding contains:

- `category` — `security | maintenance | performance | seo | infrastructure`
- `severity` — `info | low | medium | high | critical`
- `confidence` — `inferred | corroborated | confirmed`
- `sourceLayer` — `1 | 2 | 3 | third-party`
- `businessImpact` — `none | weak | medium | strong`
- `recommendation`
- `evidence` — the concrete observation(s) supporting it
- `component` (optional) — present only on a merged WordPress core/plugin/theme finding: `{ kind, slug, isOutdated, vulnerabilities }`, where `vulnerabilities` is `Array<{ severity, confirmed }>` — one entry per applicable, deduplicated vulnerability (see "Component findings" below). `confirmed` mirrors the same "version confirmed **and** applicable" check that selects a vulnerability's confirmed/potential evidence wording; `rating-engine.ts`'s Security rule reads this raw list directly, never the finding's own (possibly escalated) `severity`.

**Severity comes from the vulnerability's own data — confidence never adjusts it.** There is no confidence-caps-severity mechanism (removed; a prior version of this rule capped a `critical` CVE down to `medium` purely because the installed version was only `inferred`, which mixed up two unrelated questions). Resolution order (`analysis/vulnerability-severity.ts`'s `resolveVulnerabilitySeverity`, backed by `analysis/cvss-severity.ts`'s fixed CVSS table):

1. CVSS base score, mapped via the fixed table: `9.0–10.0 → critical`, `7.0–8.9 → high`, `4.0–6.9 → medium`, `0.1–3.9 → low`, `0 → info`.
2. A WPScan-provided severity string, if present (not currently exposed by the real WPScan v3 API — verified live — but the fallback chain is built for it regardless).
3. A conservative floor from WPScan's `vuln_type` for a small allowlist of inherently serious classes (RCE, SQLi, auth bypass, priv-esc, SSRF, XXE) → `high` — never `critical` from this signal alone.
4. `medium`, if nothing else applies. Never invented beyond this.

Confidence still matters, just for two different things: it selects report wording — `confirmed` (version confirmed **and** the vulnerability is applicable) → "has a known vulnerability"; anything less → "may be affected by a known vulnerability" — and it feeds Performance/SEO's real-measurement banding (see "Scoring" below) where relevant. It never adjusts severity. Never mark a version `confirmed` off a bare `?ver=` alone (unchanged rule, enforced in `analysis/version-confidence.ts`).

**Applicability (independent of confidence):** a vulnerability is included for a component only when the detected version falls inside the affected range (`installed < fixed_in`, or no fix published yet) — `analysis/finding-engine.ts`'s `isAffectedByVulnerability`. This gate decides inclusion and the confirmed/potential wording; it never touches severity.

**Component findings — one per component, not one per vulnerability.** `analysis/finding-engine.ts`'s `assembleComponentFinding` merges a component's outdated-status and its deduplicated (`analysis/vulnerability-dedup.ts`), applicable vulnerabilities into a single Finding — never a separate "outdated" finding plus a separate finding per vulnerability for the same underlying problem. The finding's displayed `severity` is the max across its applicable vulnerabilities' resolved severities, **escalated from `medium` to `high` once there are `MEDIUM_ESCALATION_THRESHOLD` (3) or more medium-severity vulnerabilities** — narrower than it sounds: 1 or 2 mediums stay `medium`; a single high/critical is already visible on its own and is never escalated further by count. This escalation only changes the displayed badge — scoring/rating logic reads the raw per-vulnerability list, never this label. With zero vulnerabilities but an outdated version, it's a fixed `medium` `maintenance` finding (unchanged from before).

**WPScan and wordpress.org are independent enrichment tracks.** WPScan is authoritative for vulnerabilities (CVE, CVSS, range, `fixed_in`); wordpress.org is authoritative for "latest version." A missing wordpress.org listing for a component (premium/closed plugins — Elementor Pro and friends — always 404 there) must never block a WPScan lookup, and never has (`enrichPluginVulnerabilities`/`enrichThemeVulnerabilities` read detected slugs directly, not wordpress.org's enrichment map). What _did_ need fixing: without a wordpress.org listing, `isOutdated` stayed `false` forever even when WPScan clearly showed the installed version behind a known fix. `wpscanBasedOutdatedStatus` (`analysis/finding-engine.ts`) now falls back to the highest `fixed_in` among a component's applicable vulnerabilities in that case — evidence key `finding.component.{plugin,theme}.outdatedStatus.fromFixedIn.evidence`, distinct from the ordinary wordpress.org-based `...outdatedStatus.evidence`.

**Dedup between the two tracks:** when WPScan already has ≥1 applicable vulnerability for **core**, wordpress.org's generic "insecure" evidence line is suppressed in favor of the plain "outdated" line — the itemized WPScan CVEs already say the same thing better, and asserting it twice is redundant. Core is still tracked as outdated either way; only the wording changes. (Plugins/themes don't have this "insecure vs. outdated" distinction to begin with, so there's nothing to suppress for them.)

**Known limitation:** WPScan's registered slug for a plugin can differ from the slug our scanners detect from `/wp-content/...` paths. A mismatch produces an ordinary 404, which reads identically to "no known vulnerabilities" — there is no signal in the API response that would let us tell the two apart. This only affects individual components; the run-level `not_assessed` coverage flag (see "Ratings" below) only trips on _total_ WPScan failure, not a single slug mismatch.

**TLS/HTTPS findings are `infrastructure` category, not `security`** (`deriveTlsFindings` in `analysis/finding-engine.ts`) — matches the Infrastructure rating rule below, which is what actually looks for this category. A genuinely HTTP-only site (never upgrades to HTTPS) gets its own finding, `finding.infrastructure.noHttps`, derived directly from the _effective_ (post-redirect) URL rather than from `tls-scanner`, which correctly never runs at all in that case (nothing to probe).

**Missing security headers and header info-disclosure are hygiene, not risk.** They're still real Findings (`category: 'security'`, same data model, same JSON) — they just never drive any rating (see "Ratings" below, which simply never looks at them) and never surface as a headline insight (`insight-engine.ts` has no rule for them). The HTML/PDF report routes them to a separate "Quick Wins" section (`html-report.ts`'s `isHygieneFinding`, matched on `recommendationKey` prefix) instead of the main Findings list, so a genuinely clean site (no known vulnerabilities) isn't made to look risky by one missing header.

---

# Ratings

Security, Maintenance, Infrastructure, and Overall are **qualitative**, not point-scored — `analysis/rating-engine.ts`, one function per category (`rateSecurity`, `rateMaintenance`, `rateInfrastructure`, `rateOverall`, plus `calculateRatings`), all plain first-match rules, no hidden weights, no arithmetic. A category's level is one of:

- `clear` — "Bez istotnych zastrzeżeń" (no significant concerns)
- `attention` — "Wymaga uwagi" (needs attention)
- `urgent` — "Wymaga pilnych działań" (needs urgent action)
- `not_assessed` — "Nieoceniane" — the relevant check never actually ran this pass (prospect mode, no WPScan token, every wordpress.org lookup failed, TLS probe errored). **Never** shown as `clear`; a category with no findings is only `clear` when we know we actually checked.

Every category carries `reasons: RatingReason[]` (the same `{key, params}` shape as Finding evidence, never a raw string) — the concrete facts that drove the level, so the report can show "why."

Every rule follows the same shape: a finding-based signal always wins first (if something was found, say so); `not_assessed` is only the fallback when _nothing_ was found _and_ the relevant check is known not to have run.

- **Security** — depends **only** on actual vulnerabilities (WPScan component data, plus NVD/CISA-KEV PHP vulnerabilities — see External APIs) and endpoint-scanner exposures (config backup, xmlrpc, user enumeration, directory listing) — **never** on missing headers (those are hygiene, above).
  - `urgent`: any vulnerability with `(confirmed || knownExploited) && severity in {high, critical}`, or any endpoint finding with `severity in {high, critical}`.
  - `attention`: any vulnerability at all (potential, or medium/low), or any endpoint finding at all.
  - else `not_assessed` if WPScan coverage is missing (`SECURITY_COVERAGE_ENRICHMENT`, written by the orchestrator: `not_assessed` when WPScan was never attempted — prospect mode or no token — or attempted and every single lookup failed), else `clear`.
  - The `urgent` threshold reads each vulnerability's _raw_ confirmed+severity pair, **not** the component Finding's escalated severity badge — a component can show "High" on its badge (escalated from several mediums) while Security stays `attention`. Deliberate.
  - **`knownExploited` is a deliberate exception to the confirmed-only rule, scoped to PHP.** A detected PHP version is realistically always single-source (`http-header`, capped at `inferred` — see Version detection), so it can never reach `confirmed` on its own, which would otherwise make it permanently unable to drive Security to `urgent` regardless of severity. `knownExploited: true` means CISA's KEV catalog has _confirmed_ active exploitation in the wild — treated as at least as strong a signal as our own `confirmed` bar. `false`/absent for every WordPress core/plugin/theme vulnerability (WPScan doesn't expose this), so this exception has no effect outside the PHP check. Decided explicitly with the user rather than assumed.
- **Maintenance** — a separate axis from vulnerabilities entirely (a component can be outdated with zero known CVEs, or vulnerable without wordpress.org knowing about it at all).
  - `urgent`: WordPress core itself is outdated, **or** `>= MAINTENANCE_URGENT_OUTDATED` (6) components are outdated — **both counted only among components whose version `confidence !== 'inferred'`**. Found live: a real client site's cached homepage still served an old asset `?ver=` after the site had actually been upgraded (confirmed via `wp-admin`) — an `inferred`, single-source version ("cache-busters lie," see Version detection) is not solid enough ground to assert "core outdated, urgent" on its own, mirroring how Security's `urgent` threshold already requires a vulnerability to be `confirmed`, not merely potential.
  - `attention`: `outdatedComponentCount >= 1` — this branch does **not** filter by confidence; an inferred-only outdated signal still surfaces as a softer, non-headline note rather than being dropped entirely.
  - else `not_assessed` if wordpress.org coverage is missing (`MAINTENANCE_COVERAGE_ENRICHMENT`: `not_assessed` only when there was ≥1 component to check and _every_ lookup for it failed), else `clear`.
- **Infrastructure** — **no `urgent` tier exists for this category** (spec only defines attention/clear/not_assessed; TLS/HTTPS problems are real but capped at `attention` by design).
  - `attention`: any `infrastructure`-category finding present (TLS cert/protocol issues, or the "no HTTPS" finding).
  - else `not_assessed` if the effective (post-redirect) URL is `https:` but `tls-scanner` produced no successful result, else `clear`.
- **Overall** — worst of the three via `urgent > attention > clear`, **ignoring** any category that is `not_assessed`; becomes `not_assessed` itself only when all three are.

---

# Scoring

Numeric 0-100 scores now exist **only** where the number is a real, deterministic external measurement — currently just **Performance** via Google Lighthouse/PageSpeed. `analysis/scoring-engine.ts`'s `calculateMeasuredScores` returns the real `performanceScore` directly, never a synthetic deduction — previously a _good_ score (≥90) produced no Finding at all, which meant the actual number was invisible everywhere in a clean run; this makes it visible unconditionally. **SEO** has no real Lighthouse SEO category wired up yet, so it isn't modeled here at all — the report renders a static "not assessed" row for it rather than faking a number.

Bands for these measured numbers (`analysis/score-band.ts`, unchanged thresholds, relabeled): `0–49 → poor` ("Wymaga działania" / needs action), `50–89 → fair` ("Wymaga weryfikacji" / needs review), `90–100 → good` ("Bez istotnych zastrzeżeń" / no significant concerns). This is a **different** three-level scale from the qualitative rating levels above — don't conflate the two; they use different labels on purpose.

Security/Maintenance/Infrastructure/Overall are **not** scored numerically at all anymore (no `BASE_PENALTY`/`CONFIDENCE_WEIGHT`/deduction math) — see "Ratings" above.

**Report counters** (`analysis/finding-engine.ts`'s `calculateReportCounters`, attached to `AuditResult.counters`): `componentsWithVulnerabilities`, `uniqueVulnerabilityCount` (deduplicated — CVE → WPScan id → normalized title — across every component, not just within one, so the same CVE affecting two components still counts once), `outdatedComponentCount`, `findingsBySeverity`. Three genuinely different axes — never conflate "components with vulnerabilities" with "unique vulnerabilities" (e.g. "22 vulnerabilities across 8 components," not just "8"). Not routed through `AuditContext` — see the AuditContext vs AuditResult section's note on `ratings`/`measuredScores` following the same pattern.

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

Current rules (`INSIGHT_RULES` in `insight-engine.ts`) group Findings by theme rather than emitting one insight per finding: known vulnerabilities, priority (critical/high severity), outdated components, TLS/HTTPS configuration (matches `category === 'infrastructure'`, so it covers both TLS cert/protocol findings and the "no HTTPS" finding), exposed endpoints. A single Finding can legitimately surface under more than one rule (e.g. a critical exposed-endpoint finding appears in both the priority bucket and the exposed-endpoints bucket) — that's intentional, not a dedup bug.

**Missing security headers and header info-disclosure have no rule here** — they're hygiene, not headline-worthy risk (see "Findings" above); they still appear in the report's own "Quick Wins" section, just not as an Insight.

`insight.knownVulnerabilities` reports `componentCount` and `vulnCount` as two separate params, not one ambiguous `count` — "22 vulnerabilities across 8 components," never just "8" (which used to silently mean "components," undercounting the real number of known vulnerabilities). Every other rule still uses the default `{ count: matched.length }` shape (`InsightRule.params`, optional, only overridden where a rule genuinely needs a different one).

---

# Reports

Generate: JSON, HTML, PDF.

HTML/PDF contain: summary, qualitative ratings (Security/Maintenance/Infrastructure/Overall, with reasons), measured scores (Performance's real number; SEO as "not assessed"), risk findings, a separate "Quick Wins" hygiene section (missing headers/info-disclosure — see "Findings"), detected plugins, detected theme, recommendations, sales insights, limitations.

Always include a disclaimer that the audit is based only on publicly available information. Keep the HTML template PDF-friendly so PDF is a render of the same template, not a separate layout.

**The consent artifact is intentionally not rendered in the HTML/PDF report** (deliberate product decision — the report is client-facing). It's still captured and persisted on `AuditResult`/JSON, which is what actually satisfies audit mode's auditable-trail requirement (see "Consent artifact" above) — `renderDisclaimer` in `reports/html-report.ts` no longer branches on `result.consentArtifact` at all, and there is no consent section in the template.

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
NVD_API_KEY=              # optional; raises the NVD rate ceiling, never gates the PHP check on/off

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

**Phase 2** — WPScan API, PageSpeed, cache, scoring. **✅ Done.** WPScan CVE enrichment: audit-mode-gated, verified against the live API. PageSpeed: prospect-safe, verified against the live API, feeds real findings into the `performance` score category (previously always 100). Cache (`FileCacheStore`, `provider:type:identifier:version` keys): done. Scoring as originally built here (a `BASE_PENALTY`×`CONFIDENCE_WEIGHT` deduction table producing a 0-100 number for every category) was later replaced by qualitative ratings for Security/Maintenance/Infrastructure/Overall — see "Ratings" and "Scoring" above; `analysis/scoring-engine.ts` now only computes Performance's real measured number.

**Phase 3** — batch mode (with consent handling), history, compare, deep profile. **Deep profile: done** (see Axis 2 above — `PluginScanner`/`ThemeScanner` asset-scanning at prospect+deep, Layer 3 dictionary enumeration at audit+deep, verified live). **Batch mode, history, compare: not started.** `wp-audit batch`/`wp-audit history` are registered commands that just print "not implemented."

**Phase 4** — SQLite, PDF export, AI-generated sales email. **Not started.** `pdf-report.ts` is an intentional stub (own docstring says Phase 4); the HTML template it will render is already built and print-friendly, so PDF should be "render the same template," not a new layout, once an engine is chosen.

**Post-Phase-3 addition** — PHP vulnerability detection (NVD + CISA KEV). **✅ Done.** Prospect-safe (reads PHP's version off the already-fetched `X-Powered-By` header, no new request); see "External APIs" above for the client and "Ratings" above for the KEV-confirmed-exploitation exception to Security's confirmed-only `urgent` rule.

---

# Philosophy

Optimize for correctness, maintainability, modularity, evidence, developer experience.

Not for maximum findings, sensational reports, or aggressive scanning.

Every reported issue should help start a meaningful, honest conversation with a potential client — and every network request should be one we could defend if the target's owner asked why we made it.
