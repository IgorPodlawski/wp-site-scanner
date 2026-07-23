import { readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { ensureDir } from './paths.js';

export interface CacheStore {
  get<T>(key: string): Promise<T | undefined>;
  set<T>(key: string, value: T, ttlMs: number): Promise<void>;
}

interface CacheEnvelope<T> {
  value: T;
  expiresAt: number;
}

function keyToFileName(key: string): string {
  return `${encodeURIComponent(key)}.json`;
}

/** Mandatory per CLAUDE.md, even in Phase 1-3 (file-based; may move into SQLite in Phase 4). */
export class FileCacheStore implements CacheStore {
  constructor(private readonly cacheDir: string) {}

  async get<T>(key: string): Promise<T | undefined> {
    const filePath = path.join(this.cacheDir, keyToFileName(key));
    try {
      const raw = await readFile(filePath, 'utf-8');
      const envelope = JSON.parse(raw) as CacheEnvelope<T>;
      if (Date.now() >= envelope.expiresAt) {
        return undefined;
      }
      return envelope.value;
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === 'ENOENT') {
        return undefined;
      }
      throw error;
    }
  }

  async set<T>(key: string, value: T, ttlMs: number): Promise<void> {
    await ensureDir(this.cacheDir);
    const envelope: CacheEnvelope<T> = { value, expiresAt: Date.now() + ttlMs };
    const filePath = path.join(this.cacheDir, keyToFileName(key));
    await writeFile(filePath, JSON.stringify(envelope), 'utf-8');
  }
}
