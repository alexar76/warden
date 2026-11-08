// GENERATED from src/flow-guard-unattended.ts by scripts/sync-flow-guard.mjs. Do not edit; run npm run build.
/** Reasons that are about data, never only about an action. */
export const DATA_REASONS = new Set(['protected_settings', 'secret', 'secret_fragment',
    'paste_after_secret', 'payload_incomplete', 'secret_tracking', 'personal_data', 'private_text', 'credential_egress',
    'secret_to_file']);
/** Whether an unattended run must refuse this decision. */
export function refuses(decision, detail, block) {
    if (decision.permissionDecision === 'deny' || block === 'all')
        return true;
    return !!detail.sensitive || (detail.reason !== undefined && DATA_REASONS.has(detail.reason));
}
/** `data` or `all` from an environment value; anything else is undefined. */
export function blockMode(value) {
    return value === 'all' || value === 'data' ? value : undefined;
}
/** File paths an apply_patch text adds, updates, moves or deletes. */
export function patchFiles(patch) {
    const out = [];
    for (const m of patch.matchAll(/^\*\*\* (?:Add|Update|Delete) File: (.+)$|^\*\*\* Move to: (.+)$/gm))
        out.push((m[1] ?? m[2]).trim());
    return [...new Set(out)];
}
