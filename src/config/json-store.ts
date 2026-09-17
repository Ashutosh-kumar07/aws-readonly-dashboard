/**
 * A tiny JSON document store.
 *
 * Deliberately not SQLite: configuration is small, human-inspectable, and must
 * remain easy to delete. Writes are atomic (temp file + rename) and files are
 * created with owner-only permissions.
 */

import { constants as fsConstants } from 'node:fs';
import { chmod, mkdir, readFile, rename, rm, writeFile, access } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { randomBytes } from 'node:crypto';

import { logger } from '../util/logger.js';

const DIR_MODE = 0o700;
const FILE_MODE = 0o600;

export async function ensureDir(dir: string): Promise<void> {
  await mkdir(dir, { recursive: true, mode: DIR_MODE });
  try {
    await chmod(dir, DIR_MODE);
  } catch {
    // Permission tightening is best-effort (e.g. on Windows).
  }
}

export async function fileExists(path: string): Promise<boolean> {
  try {
    await access(path, fsConstants.F_OK);
    return true;
  } catch {
    return false;
  }
}

export async function readJsonFile<T>(path: string): Promise<T | undefined> {
  try {
    const contents = await readFile(path, 'utf8');
    if (!contents.trim()) return undefined;
    return JSON.parse(contents) as T;
  } catch (error) {
    const code = (error as NodeJS.ErrnoException).code;
    if (code === 'ENOENT') return undefined;
    logger.warn(`Could not read ${path}; falling back to defaults`, {
      reason: (error as Error).message,
    });
    return undefined;
  }
}

/** Atomically writes a JSON document with owner-only permissions. */
export async function writeJsonFile(path: string, value: unknown): Promise<void> {
  const dir = dirname(path);
  await ensureDir(dir);
  const temp = join(dir, `.${randomBytes(6).toString('hex')}.tmp`);
  const serialised = `${JSON.stringify(value, null, 2)}\n`;
  await writeFile(temp, serialised, { encoding: 'utf8', mode: FILE_MODE });
  try {
    await chmod(temp, FILE_MODE);
  } catch {
    // Best-effort on platforms without POSIX permissions.
  }
  await rename(temp, path);
}

export async function deleteFile(path: string): Promise<boolean> {
  try {
    await rm(path, { force: true });
    return true;
  } catch {
    return false;
  }
}

export async function deleteDir(path: string): Promise<boolean> {
  try {
    await rm(path, { recursive: true, force: true });
    return true;
  } catch {
    return false;
  }
}
