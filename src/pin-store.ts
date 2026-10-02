import { createHash } from 'node:crypto';
import { join } from 'node:path';
import { unlink } from 'node:fs/promises';
import { defaultStateDir, readState, writeState, withStateLock } from './state.js';
import { canonicalizeRfc8785 } from './jcs.js';
import type { PinStore, PinnedServer } from './types.js';

export function pinRevision(pin: PinnedServer | undefined): string | null {
  return pin ? createHash('sha256').update(canonicalizeRfc8785(pin)).digest('hex') : null;
}

/** One atomic file per server; hashed filenames cannot escape the state directory. */
export class FilePinStore implements PinStore {
  constructor(private readonly dir = join(defaultStateDir(), 'pins')) {}
  private path(id: string): string { return join(this.dir, `${createHash('sha256').update(id).digest('hex')}.json`); }
  async getPin(id: string): Promise<PinnedServer | undefined> {
    const pin = await readState<PinnedServer>(this.path(id));
    if (pin !== undefined && (!pin || typeof pin !== 'object' || pin.serverId !== id ||
        typeof pin.toolsHash !== 'string' || !/^(?:rfc8785:)?[a-f0-9]{64}$/.test(pin.toolsHash) ||
        typeof pin.approvedAt !== 'string' || !Array.isArray(pin.toolNames) || !pin.toolNames.every(n => typeof n === 'string'))) {
      throw new Error('Invalid pin state; refusing to treat it as first contact');
    }
    return pin;
  }
  async putPin(pin: PinnedServer): Promise<void> {
    await withStateLock(this.path(pin.serverId), () => writeState(this.path(pin.serverId), pin));
  }
  /** Compare-and-swap prevents approval/revocation of state that changed since review. */
  async replace(id: string, expected: string | null, pin?: PinnedServer): Promise<void> {
    if (pin && pin.serverId !== id) throw new Error("Pin server ID does not match target");
    await withStateLock(this.path(id), async () => {
      const current = await this.getPin(id);
      if (pinRevision(current) !== expected) throw new Error('Pin changed since review; inspect status again');
      if (pin) await writeState(this.path(id), pin);
      else await unlink(this.path(id)).catch(err => { if (err.code !== 'ENOENT') throw err; });
    });
  }
}
