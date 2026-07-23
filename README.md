# wp-site-scanner (wp-audit)

Black-box WordPress quality assessment CLI. It scans a target from the public Internet, detects WordPress core/plugin/theme versions, checks security headers and TLS, cross-references known WordPress.org and WPScan data, and produces a JSON + HTML report. See [CLAUDE.md](./CLAUDE.md) for the full project spec (mission, architecture, authorization model, and the current implementation status of every phase).

## Status

The `audit` command works end-to-end today: all scanners, the orchestrator, WordPress.org + WPScan enrichment, findings, scoring, insights, and both JSON and HTML report generation are implemented. **`batch` and `history` are not implemented yet** — they're registered CLI commands that just print a "not implemented" message. See CLAUDE.md's Roadmap section for the up-to-date phase-by-phase status.

## Prerequisites

- Node.js 22+
- pnpm

## Setup

```bash
pnpm install
cp .env.example .env
```

All `.env` values are optional to get started — the CLI validates them but never crashes on missing ones. Two are worth knowing about:

- `WPSCAN_API_TOKEN` — without it, CVE/vulnerability findings are simply skipped (and only apply in `--i-have-authorization` runs to begin with; see "Authorization modes" below). Free tier is rate-limited (~100 requests/day) — results are cached for 7 days.
- `PAGESPEED_API_KEY` — not used yet; the PageSpeed integration isn't implemented, so this currently does nothing.

## Usage

```bash
# Prospect mode (default) — no prior consent needed, no path guessing
pnpm dev -- audit https://example.com
pnpm dev -- audit https://example.com --profile deep --lang pl

# Audit mode — only on targets you own or have written permission to test
pnpm dev -- audit https://example.com --i-have-authorization

# Disable the cache / force a refresh
pnpm dev -- audit https://example.com --no-cache
```

Every run writes:

- `data/audits/<domain>/<timestamp>.json` — the full machine-readable result
- `reports/<domain>/<timestamp>.html` — a print-friendly HTML report in the chosen `--lang`

and prints both paths.

**Authorization modes matter — read CLAUDE.md's "Two operating axes" section before changing anything here.** `prospect` (default) only does what a normal browser would do; `audit` unlocks targeted probes (readme.txt, `/wp-json/wp/v2/users`, xmlrpc.php, directory listing, config backups, WPScan CVE lookups) and requires `--i-have-authorization`. `--profile quick|standard|deep` is accepted but doesn't currently change scanner behavior (not implemented yet).

Run the built CLI instead of `pnpm dev` (tsx) once compiled:

```bash
pnpm build
node dist/cli/index.js audit https://example.com
```

(There's a `wp-audit` entry in `package.json`'s `bin` field, but this project isn't linked/installed as a package, so `pnpm wp-audit` won't resolve it — use `node dist/cli/index.js` instead.)

## Development

```bash
pnpm typecheck
pnpm lint
pnpm test                                          # all tests
pnpm test tests/unit/finding-engine.test.ts         # a single file
pnpm test:watch
pnpm format                                         # or format:check
```

Tests never hit live sites or real external APIs — scanners and integration clients are tested by dependency-injecting fake `HttpClient`/`CacheStore` objects. See CLAUDE.md's Testing section for the full policy, including a couple of real bugs that were only caught by manually verifying against the live WordPress.org/WPScan APIs before trusting the assumed response shape.
