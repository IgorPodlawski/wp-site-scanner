import { t } from '../i18n/translate.js';

export function printMessage(key: string, params?: Record<string, string | number>): void {
  console.log(t(key, params));
}

export function printError(message: string): void {
  console.error(message);
}
