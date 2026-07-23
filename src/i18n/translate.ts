import type { Locale, LocaleMessages } from './types.js';
import { loadLocale } from './loader.js';

let activeLocale: Locale = 'en';
let activeMessages: LocaleMessages = {};

export async function setLocale(locale: Locale): Promise<void> {
  activeMessages = await loadLocale(locale);
  activeLocale = locale;
}

export function getLocale(): Locale {
  return activeLocale;
}

/** Translates a message key with `{{param}}` interpolation. Never hardcode user-facing strings — always go through this. */
export function t(key: string, params?: Record<string, string | number>): string {
  const template = activeMessages[key] ?? key;
  if (!params) {
    return template;
  }
  return template.replace(/\{\{(\w+)\}\}/g, (match, paramName: string) =>
    paramName in params ? String(params[paramName]) : match,
  );
}
