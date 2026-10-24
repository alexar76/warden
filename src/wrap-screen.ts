import { closeSync, mkdirSync, openSync, unlinkSync } from 'node:fs';
import { flowPaths, stateDir } from './flow-guard.js';

/** Serialize known GUI effects across proxies sharing a session. Never reclaim a possibly live/crashed lease. */
export function screenLease(session: string, env: NodeJS.ProcessEnv = process.env): (abandon?: boolean) => void {
  const paths = flowPaths(stateDir(env), session);
  mkdirSync(paths.dir, { recursive: true, mode: 0o700 });
  const path = paths.state + '.screen-approval.lock';
  let fd: number;
  try { fd = openSync(path, 'wx', 0o600); } catch { throw new Error('WARDEN: another GUI action is pending or an uncertain screen lease needs operator review; this action was not run'); }
  let released = false;
  return (abandon = false) => { if (released) return; released = true; closeSync(fd); if (!abandon) unlinkSync(path); };
}
