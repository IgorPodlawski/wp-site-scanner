import { ok, err, type Result } from './result.js';

/** Retries at most once, per CLAUDE.md's "every external API must ... retry at most once". */
export async function withRetry<T>(fetcher: () => Promise<T>): Promise<Result<T, Error>> {
  try {
    return ok(await fetcher());
  } catch {
    // one retry
  }
  try {
    return ok(await fetcher());
  } catch (error) {
    return err(error instanceof Error ? error : new Error(String(error)));
  }
}
