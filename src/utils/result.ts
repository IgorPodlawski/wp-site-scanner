/**
 * Explicit success/failure type for flows where a failure should be handled
 * by the caller rather than thrown — e.g. a scanner's internal steps, where
 * a failure must become a `ScannerResult` with status 'error' rather than an
 * exception crossing the scanner boundary and aborting the whole audit.
 */
export type Result<T, E = Error> = { ok: true; value: T } | { ok: false; error: E };

export function ok<T>(value: T): Result<T, never> {
  return { ok: true, value };
}

export function err<E>(error: E): Result<never, E> {
  return { ok: false, error };
}
