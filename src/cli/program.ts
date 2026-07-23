import { Command } from 'commander';
import { registerAuditCommand } from './commands/audit.js';
import { registerBatchCommand } from './commands/batch.js';
import { registerHistoryCommand } from './commands/history.js';

export function buildProgram(): Command {
  const program = new Command();
  program
    .name('wp-audit')
    .description('Black-box WordPress quality assessment CLI')
    .version('0.1.0');

  registerAuditCommand(program);
  registerBatchCommand(program);
  registerHistoryCommand(program);

  return program;
}
