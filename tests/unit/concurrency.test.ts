import { describe, expect, it } from 'vitest';
import { mapWithConcurrency } from '@utils/concurrency.js';

describe('mapWithConcurrency', () => {
  it('preserves input order regardless of completion order', async () => {
    const delays = [30, 10, 20, 0];
    const result = await mapWithConcurrency(delays, 4, async (ms, i) => {
      await new Promise((resolve) => setTimeout(resolve, ms));
      return i;
    });

    expect(result).toEqual([0, 1, 2, 3]);
  });

  it('never runs more than `limit` tasks concurrently', async () => {
    let inFlight = 0;
    let maxInFlight = 0;

    await mapWithConcurrency([1, 2, 3, 4, 5, 6, 7, 8], 3, async (item) => {
      inFlight += 1;
      maxInFlight = Math.max(maxInFlight, inFlight);
      await new Promise((resolve) => setTimeout(resolve, 5));
      inFlight -= 1;
      return item;
    });

    expect(maxInFlight).toBeLessThanOrEqual(3);
  });

  it('returns an empty array for an empty input without calling fn', async () => {
    let called = false;
    const result = await mapWithConcurrency([], 5, async () => {
      called = true;
      return 1;
    });

    expect(result).toEqual([]);
    expect(called).toBe(false);
  });

  it('handles a limit larger than the item count', async () => {
    const result = await mapWithConcurrency([1, 2], 10, async (n) => n * 2);
    expect(result).toEqual([2, 4]);
  });
});
