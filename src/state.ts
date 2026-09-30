import { mkdir, open, readFile, rename, unlink } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { homedir } from 'node:os';
import { randomUUID } from 'node:crypto';

export function defaultStateDir(): string {
  return process.env.WARDEN_STATE_DIR || join(process.env.XDG_STATE_HOME || join(homedir(), '.local', 'state'), 'warden');
}

export async function readState<T>(path: string): Promise<T | undefined> {
  try { return JSON.parse(await readFile(path, 'utf8')) as T; }
  catch (err) { if ((err as NodeJS.ErrnoException).code === 'ENOENT') return undefined; throw err; }
}

/** Atomic replace; a failed write never destroys the previous approval/snapshot. */
export async function writeState(path: string, value: unknown): Promise<void> {
  await mkdir(dirname(path), { recursive: true, mode: 0o700 });
  const temp = `${path}.${randomUUID()}.tmp`;
  try {
    const file = await open(temp, 'wx', 0o600);
    try { await file.writeFile(JSON.stringify(value)); await file.sync(); }
    finally { await file.close(); }
    await rename(temp, path);
  } finally { await unlink(temp).catch(() => {}); }
}

/** Serialize read/compare/write across processes. A leftover lock fails closed. */
export async function withStateLock<T>(path: string, action: () => Promise<T>): Promise<T> {
  await mkdir(dirname(path), { recursive: true, mode: 0o700 });
  const lock = `${path}.lock`;
  let file;
  for (let attempt = 0; ; attempt++) {
    try { file = await open(lock, 'wx', 0o600); break; }
    catch (err) {
      if ((err as NodeJS.ErrnoException).code !== 'EEXIST' || attempt >= 100) throw err;
      await new Promise(resolve => setTimeout(resolve, 20));
    }
  }
  try { return await action(); }
  finally { await file.close(); await unlink(lock); }
}
