# wp-site-scanner (wp-audit)

Black-box WordPress quality assessment CLI. See [CLAUDE.md](./CLAUDE.md) for the full project spec.

## Prerequisites

- Node.js 22+
- pnpm

## Setup

```bash
pnpm install
cp .env.example .env
```

## Usage

```bash
pnpm dev -- audit https://example.com
pnpm dev -- audit https://example.com --profile deep --lang pl
pnpm build && pnpm wp-audit audit https://example.com
```

## Development

```bash
pnpm typecheck
pnpm lint
pnpm test
```
