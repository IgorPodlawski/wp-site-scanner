/**
 * Maps `items` through `fn` with at most `limit` in flight at once —
 * used where firing every request simultaneously would be impolite (e.g.
 * Layer-3 dictionary enumeration against a real target under audit
 * consent). Results preserve input order regardless of completion order.
 */
export async function mapWithConcurrency<T, R>(
  items: readonly T[],
  limit: number,
  fn: (item: T, index: number) => Promise<R>,
): Promise<R[]> {
  const results: R[] = new Array(items.length);
  let nextIndex = 0;

  async function worker(): Promise<void> {
    for (;;) {
      const current = nextIndex++;
      if (current >= items.length) return;
      results[current] = await fn(items[current]!, current);
    }
  }

  await Promise.all(Array.from({ length: Math.min(limit, items.length) }, worker));
  return results;
}
