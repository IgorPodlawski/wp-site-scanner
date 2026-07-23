import pino, { type LoggerOptions } from 'pino';
import type { AppConfig } from '../config/types.js';

export function createLogger(config: Pick<AppConfig, 'LOG_LEVEL'>) {
  const options: LoggerOptions = { level: config.LOG_LEVEL };

  if (process.stdout.isTTY) {
    options.transport = {
      target: 'pino-pretty',
      options: { colorize: true, translateTime: 'HH:MM:ss', ignore: 'pid,hostname' },
    };
  }

  return pino(options);
}

export type Logger = ReturnType<typeof createLogger>;
