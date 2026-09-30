import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterAll } from 'vitest';
const dir = mkdtempSync(join(tmpdir(), 'warden-test-state-'));
process.env.WARDEN_STATE_DIR = dir;
afterAll(() => rmSync(dir, { recursive: true, force: true }));
