import { readFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { z } from 'zod';
import type { Locale, LocaleMessages } from './types.js';

const localeMessagesSchema = z.record(z.string(), z.string());

// src/i18n/loader.ts and dist/i18n/loader.js are both two directories below
// the project root, where locales/ lives — so the relative path holds for
// both dev (tsx over src/) and built (node over dist/) execution.
const LOCALES_DIR = path.join(path.dirname(fileURLToPath(import.meta.url)), '../../locales');

const cache = new Map<Locale, LocaleMessages>();

export async function loadLocale(locale: Locale): Promise<LocaleMessages> {
  const cached = cache.get(locale);
  if (cached) {
    return cached;
  }

  const filePath = path.join(LOCALES_DIR, `${locale}.json`);
  const raw = await readFile(filePath, 'utf-8');
  const messages = localeMessagesSchema.parse(JSON.parse(raw));

  cache.set(locale, messages);
  return messages;
}
