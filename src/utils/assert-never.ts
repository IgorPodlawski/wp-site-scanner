/** Exhaustiveness check for switch statements over discriminated unions. */
export function assertNever(value: never): never {
  throw new Error(`Unhandled case: ${JSON.stringify(value)}`);
}
