/**
 * `pnpm <script> -- <args>` (the documented way to run this CLI in dev)
 * forwards that `--` through verbatim rather than stripping it. Commander
 * treats a bare `--` as "end of options" per POSIX convention, so
 * everything after it — including `--profile`/`--lang` — gets treated as
 * literal positional arguments instead of being parsed as flags, and
 * `audit <url>` (which takes exactly one positional argument) rejects the
 * rest as "too many arguments". A leading `--` here only ever comes from
 * that pnpm/npm forwarding, never from the user's own intent, so it's safe
 * to drop unconditionally.
 */
export function stripLeadingPassthroughSeparator(argv: readonly string[]): string[] {
  return argv[2] === '--' ? [...argv.slice(0, 2), ...argv.slice(3)] : [...argv];
}
