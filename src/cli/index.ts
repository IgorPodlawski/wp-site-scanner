#!/usr/bin/env node
import { buildProgram } from './program.js';
import { printError } from './output.js';
import { stripLeadingPassthroughSeparator } from './argv.js';

async function main(): Promise<void> {
  const program = buildProgram();
  await program.parseAsync(stripLeadingPassthroughSeparator(process.argv));
}

main().catch((error: unknown) => {
  printError(error instanceof Error ? error.message : String(error));
  process.exitCode = 1;
});
