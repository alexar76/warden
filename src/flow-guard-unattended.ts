/**
 * Shared by the adapters for agents that run with nobody at the keyboard (OpenCode, Codex): the Claude Code hook
 * may answer `ask`, and such a runtime has no one to ask. `block` decides what an `ask` becomes.
 *
 * - `data` (default): refuse what involves data — a known secret, a credential boundary, private text or personal
 *   data in the arguments, a short credential fragment, an incomplete payload check, a change to the guard's own
 *   settings — and every decision whose payload is sensitive, whatever the first reason. Calls that only act after
 *   outside text (opaque shell code, an unnamed destination, a destructive command, a GUI action) run and are
 *   logged: an unattended agent's work is reading outside text and then reporting, and a network allowlist or a
 *   sandbox has to bound where it can act.
 * - `all`: refuse everything the Claude Code hook would ask about.
 *
 * Node built-ins and flow-guard parts only: the plugins copy this file next to their scripts.
 */
import type { FlowPreDetail, FlowReason } from './flow-guard-pre.js';

export type UnattendedBlockMode = 'data' | 'all';

/** Reasons that are about data, never only about an action. */
export const DATA_REASONS: ReadonlySet<FlowReason> = new Set<FlowReason>(['protected_settings', 'secret', 'secret_fragment',
  'paste_after_secret', 'payload_incomplete', 'secret_tracking', 'personal_data', 'private_text', 'credential_egress',
  'secret_to_file']);

/** Whether an unattended run must refuse this decision. */
export function refuses(decision: { permissionDecision: 'ask' | 'deny' }, detail: FlowPreDetail, block: UnattendedBlockMode): boolean {
  if (decision.permissionDecision === 'deny' || block === 'all') return true;
  return !!detail.sensitive || (detail.reason !== undefined && DATA_REASONS.has(detail.reason));
}

/** `data` or `all` from an environment value; anything else is undefined. */
export function blockMode(value: string | undefined): UnattendedBlockMode | undefined {
  return value === 'all' || value === 'data' ? value : undefined;
}

/** File paths an apply_patch text adds, updates, moves or deletes. */
export function patchFiles(patch: string): string[] {
  const out: string[] = [];
  for (const m of patch.matchAll(/^\*\*\* (?:Add|Update|Delete) File: (.+)$|^\*\*\* Move to: (.+)$/gm)) out.push((m[1] ?? m[2]!).trim());
  return [...new Set(out)];
}
