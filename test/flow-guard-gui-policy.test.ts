import { afterEach, describe, expect, it } from 'vitest';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { flowPaths, flowPre, loadPolicy, readFlowState, runFlowHook, type GuiActionRule, type FlowState } from '../src/flow-guard.js';

const dirs: string[] = [];
afterEach(() => { for (const dir of dirs.splice(0)) rmSync(dir, { recursive: true, force: true }); });
const click: GuiActionRule = { tool: 'mcp__screen__click', action: 'click', target: { role: 'link', accessibilityId: 'nav.inbox' }, context: { origin: 'https://mail.example' } };
const type: GuiActionRule = { tool: 'mcp__screen__type', action: 'type', target: { role: 'textbox', accessibilityId: 'search.query' }, context: { origin: 'https://mail.example' }, maxTextLength: 32 };
const key: GuiActionRule = { tool: 'mcp__screen__press_keys', action: 'key', target: click.target, context: click.context, keys: 'Tab' };
const gui = (allow: unknown[] = [click, type, key]) => ({ mode: 'policy', allow });
const box = { x: 100, y: 50, width: 60, height: 40 };
function snapshot(focus = 3) {
  return { url: 'https://mail.example/inbox', applicationId: 'dev.example.Mail', elements: [
    { index: 3, role: 'link', name: 'Inbox', accessibilityIdentifier: 'nav.inbox', bounds: { ...box }, focused: focus === 3 },
    { index: 9, role: 'textbox', name: 'Search', accessibilityIdentifier: 'search.query', multiline: false, focused: focus === 9 },
  ] };
}
function setup(policy: unknown = { gui: gui() }, extra: Record<string, string> = {}) {
  const dir = mkdtempSync(join(tmpdir(), 'warden-gui-policy-')); dirs.push(dir);
  const policyPath = join(dir, 'policy.json'); writeFileSync(policyPath, JSON.stringify(policy));
  const env = { ...process.env, WARDEN_STATE_DIR: dir, WARDEN_FLOW_POLICY: policyPath, WARDEN_FLOW_MODE: '', ...extra };
  const paths = flowPaths(dir, 'gui-policy');
  const hook = (event: string, tool: string, input: Record<string, unknown>, response?: unknown) => {
    const result = runFlowHook(event as 'pre' | 'post', JSON.stringify({ session_id: 'gui-policy', cwd: '/work/proj', tool_name: tool, tool_input: input, ...(response === undefined ? {} : { tool_response: response }) }), env);
    return result ? JSON.parse(result).hookSpecificOutput : undefined;
  };
  return { env,
    pre: (tool = click.tool, input: Record<string, unknown> = { index: 3 }) => hook('pre', tool, input)?.permissionDecision,
    post: (tool: string, input: Record<string, unknown>, response: unknown = 'done') => hook('post', tool, input, response),
    view: (data: unknown = snapshot(), tool = 'mcp__screen__screenshot') => hook('post', tool, {}, { content: [{ type: 'text', text: JSON.stringify(data) }] }),
    state: () => readFlowState(paths.state),
    mutate: (fn: (state: FlowState) => void) => { const state = readFlowState(paths.state); fn(state); writeFileSync(paths.state, JSON.stringify(state)); },
    logs: () => readFileSync(paths.log, 'utf8').trim().split('\n').map(line => JSON.parse(line)),
    reason: () => hook('pre', click.tool, { index: 3 })?.permissionDecisionReason,
    prompt: () => runFlowHook('prompt', JSON.stringify({ session_id: 'gui-policy', prompt: 'Continue browsing' }), env),
  };
}

describe('GUI policy: explicit scoped permissions', () => {
  it.each(['press_keys_then_execute', 'press_keys_then_transfer', 'keyboard_run_script', 'copy_and_press_keys'])('never interprets a composite tool %s as a passive Copy shortcut', name => {
    const s = setup({}); s.view();
    expect(s.pre(`mcp__screen__${name}`, { keys: 'cmd+c' })).toBe('ask');
  });

  it('does not grant a matching GUI request when the proxy reports additional RPC fields', () => {
    const s = setup(); s.view();
    const d = flowPre({ session_id: 'gui-policy', cwd: '/work/proj', tool_name: click.tool, tool_input: { index: 3 }, public_request_eligible: false }, s.env);
    expect(d?.permissionDecision).toBe('ask');
    expect(s.state().screens?.screen?.policyConsumed).toBeUndefined();
  });
  it('keeps strict behavior by default and when only an allow list is configured', () => {
    for (const policy of [{}, { gui: { allow: [click] } }, { gui: { mode: 'strict', allow: [click] } }]) {
      const s = setup(policy); s.view(); expect(s.pre()).toBe('ask');
    }
  });

  it('never grants from a matching fresh snapshot, identity, origin or a repeated screen read', () => {
    const s = setup(); s.view();
    expect(s.pre()).toBe('ask'); expect(s.pre()).toBe('ask');
    s.view(); expect(s.pre()).toBe('ask');
    expect(s.logs().some(e => e.disposition === 'policy_allowed')).toBe(false);
    expect(JSON.stringify(s.state().screens?.screen?.elements)).not.toContain('nav.inbox');
  });

  it.each([{ x: 120, y: 60 }, { coordinate: [120, 60] }, { position: { x: 120, y: 60 } }])('requires review for a uniquely resolved coordinate click %j only through the matching rule', input => {
    const s = setup(); s.view(); expect(s.pre(click.tool, input)).toBe('ask');
    const strict = setup({}); strict.view(); expect(strict.pre(click.tool, input)).toBe('ask');
  });

  it('supports exact application scope, and requires both scopes when both are set', () => {
    const rule = { ...click, context: { application: 'dev.example.Mail' } };
    const s = setup({ gui: gui([rule]) }); s.view({ ...snapshot(), url: undefined }); expect(s.pre()).toBe('ask');
    const both = setup({ gui: gui([{ ...rule, context: { ...rule.context, origin: 'https://mail.example' } }]) });
    both.view({ ...snapshot(), url: 'https://other.example' }); expect(both.pre()).toBe('ask');
  });

  it('supports a generic controller with an exact known action and scoped tool name', () => {
    const s = setup({ gui: gui([{ ...click, tool: 'mcp__screen__computer' }]) }); s.view();
    expect(s.pre('mcp__screen__computer', { action: 'left_click', index: 3 })).toBe('ask');
  });

  it('supports document context in structuredContent and canonical origin ports', () => {
    const s = setup({ gui: gui([{ ...click, context: { origin: 'https://mail.example:443/' } }]) });
    s.view({ structuredContent: snapshot() }); expect(s.pre()).toBe('ask');
  });

  it('counts UTF-16 units when limiting typed text', () => {
    const s = setup({ gui: gui([{ ...type, maxTextLength: 1 }]) }); s.view(snapshot(9));
    expect(s.pre(type.tool, { text: '🙂' })).toBe('ask');
    expect(s.pre(type.tool, { text: 'a' })).toBe('ask');
  });

  it.each(['Tab', ['shift', 'Tab']])('requires review even for the explicitly configured navigation chord %j on the reported focus', keys => {
    const s = setup({ gui: gui([{ ...key, keys: Array.isArray(keys) ? 'Shift+Tab' : keys }]) }); s.view();
    expect(s.pre(key.tool, { keys })).toBe('ask');
  });

  it.each([{ text: 'status' }, { value: 'status', index: 9 }])('requires review for bounded plain text %j only into the identified focused field', input => {
    const s = setup(); s.view(snapshot(9)); expect(s.pre(type.tool, input)).toBe('ask');
  });

  it.each([
    { index: 3, submit: true }, { index: 3, selector: '#send' }, { index: 3, button: 'right' },
    { index: 3, click_count: 2 }, { index: 3, action: 'right_click' }, { index: 3, ref: '3' },
    { index: 3, coordinate: [999, 999] }, { index: 3, x: '120', y: 60 },
  ])('falls back to approval for an extra or conflicting dispatch argument %j', input => {
    const s = setup(); s.view(); expect(s.pre(click.tool, input)).toBe('ask');
  });

  it.each([
    { text: 'status\n' }, { text: 'status\t' }, { text: 'x'.repeat(33) }, { text: 'status', value: 'other' },
    { text: 'status', submit: true }, { text: ['status'] }, { text: 'status', ref: '3' },
  ])('does not allow submitting, oversized or malformed text input %j', input => {
    const s = setup(); s.view(snapshot(9)); expect(s.pre(type.tool, input)).toBe('ask');
  });

  it.each([{ keys: 'Enter' }, { keys: 'ctrl+Enter' }, { keys: 'cmd+v' }, { keys: 'Tab\n' }, { keys: ['Tab', {}] }, { keys: 'Tab', text: 'payload' }])('does not allow a submission, paste or unknown key shape %j', input => {
    const s = setup(); s.view(); expect(s.pre(key.tool, input)).toBe('ask');
  });

  it.each([
    { ...click, tool: 'mcp__other__click' }, { ...click, target: { ...click.target, role: 'button' } },
    { ...click, target: { ...click.target, accessibilityId: 'Nav.Inbox' } },
    { ...click, target: { ...click.target, accessibilityId: 'nav.inbox.extra' } },
    { ...click, context: { origin: 'https://other.example' } }, { ...click, context: { application: 'dev.other.Mail' } },
  ])('does not widen a rule whose scope or target differs: %j', rule => {
    const s = setup({ gui: gui([rule]) }); s.view(); expect(s.pre()).toBe('ask');
  });

  it('never takes page authority from an element URL or a conflicting root URL', () => {
    const s = setup(), data = snapshot();
    s.view({ elements: [{ ...data.elements[0], url: data.url }] }); expect(s.pre()).toBe('ask');
    s.view({ ...data, pageUrl: 'https://other.example' }); expect(s.pre()).toBe('ask');
    s.view({ ...data, pageUrl: 'not a URL' }); expect(s.pre()).toBe('ask');
  });

  it('does not reuse metadata from another server or from a pixels-only or unknown replacement', () => {
    const s = setup(); s.view(snapshot(), 'mcp__other__screenshot'); expect(s.pre()).toBe('ask');
    s.view(); s.post('mcp__screen__screenshot', {}, { content: [{ type: 'image', data: 'iVBORw0KGgo=', mimeType: 'image/png' }] }); expect(s.pre()).toBe('ask');
    s.view({ url: snapshot().url, custom: 'opaque elements' }); expect(s.pre()).toBe('ask');
  });

  it('invalidates previous permissions on a tool error and never accepts a snapshot embedded in that error', () => {
    const s = setup(); s.view();
    const revision = s.state().screens?.screen?.revision;
    s.post('mcp__screen__screenshot', {}, { isError: true, structuredContent: snapshot() });
    expect(s.state().screens?.screen?.revision).toBe(revision);
    expect(s.pre()).toBe('ask');
    s.view(); expect(s.pre()).toBe('ask');
  });

  it.each(['expired', 'future', 'invalid', 'legacy', 'partial'])('rejects %s snapshot state', kind => {
    const s = setup(); s.view();
    s.mutate(state => { const view = state.screens!.screen!;
      if (kind === 'expired') view.at = new Date(Date.now() - 60_000).toISOString();
      if (kind === 'future') view.at = new Date(Date.now() + 60_000).toISOString();
      if (kind === 'invalid') view.at = 'invalid';
      if (kind === 'legacy') delete view.revision;
      if (kind === 'partial') delete view.policyComplete;
    });
    expect(s.pre()).toBe('ask');
  });

  it('requires a unique identity, a non-conflicting node and exact reference spelling', () => {
    const s = setup(), data = snapshot();
    s.view({ ...data, elements: [data.elements[0], { ...data.elements[0], index: 4 }] }); expect(s.pre()).toBe('ask');
    s.view({ ...data, elements: [data.elements[0], { ...data.elements[0], name: 'Different' }] }); expect(s.pre()).toBe('ask');
    s.view({ ...data, elements: [{ ...data.elements[0], accessibility_id: 'other' }] }); expect(s.pre()).toBe('ask');
    s.view({ ...data, elements: [{ ...data.elements[0], index: 'Nav' }] }); expect(s.pre(click.tool, { ref: 'nav' })).toBe('ask');
    expect(s.pre(click.tool, { ref: 'Nav' })).toBe('ask');
  });

  it('does not grant from overlapping geometry or a truncated element list', () => {
    const s = setup(), data = snapshot();
    s.view({ ...data, elements: [data.elements[0], { ...data.elements[1], bounds: box }] }); expect(s.pre(click.tool, { x: 120, y: 60 })).toBe('ask');
    s.view({ ...data, elements: [data.elements[0], ...Array.from({ length: 500 }, (_, i) => ({ index: i + 100, role: 'button' }))] }); expect(s.pre()).toBe('ask');
  });

  it.each(['Send', 'Отправить', 'Envoyer', 'Wyślij', '支付', 'Удалить'])('keeps approval for dangerous label %s even with a matching explicit target rule', name => {
    const s = setup(), data = snapshot(); s.view({ ...data, elements: [{ ...data.elements[0], name }] }); expect(s.pre()).toBe('ask');
  });

  it('keeps submission and destructive accessibility hints gated', () => {
    for (const identifier of ['compose.sendButton', 'dialog.deleteButton']) {
      const s = setup({ gui: gui([{ ...click, target: { ...click.target, accessibilityId: identifier } }]) }), data = snapshot();
      s.view({ ...data, elements: [{ ...data.elements[0], accessibilityIdentifier: identifier }] }); expect(s.pre()).toBe('ask');
    }
    const s = setup(); s.view({ ...snapshot(), elements: [{ ...snapshot().elements[0], role: 'input', type: 'submit' }] }); expect(s.pre()).toBe('ask');
  });

  it('never waives credential, private-text or PII protections', () => {
    const credentials = setup(); credentials.post('Read', { file_path: '/work/proj/.env' }, 'REGION=eu'); credentials.view(); expect(credentials.pre()).toBe('ask');
    const secret = 'gui-test-secret-marker-7491';
    const leaked = setup(); leaked.post('Read', { file_path: '/work/proj/.env' }, `TOKEN=${secret}`); leaked.view(snapshot(9)); expect(leaked.pre(type.tool, { text: secret })).toBe('deny');
    const privateText = 'Customer Q4 margin 17 percent';
    const notes = setup(); notes.post('Read', { file_path: '/work/proj/notes.md' }, privateText); notes.view(snapshot(9)); expect(notes.pre(type.tool, { text: privateText })).toBe('ask');
    const card = setup(); card.post('Read', { file_path: '/work/proj/wallet.md' }, 'Card 4111 1111 1111 1111'); card.view(snapshot(9)); expect(card.pre(type.tool, { text: '4111 1111 1111 1111' })).toBe('ask');
  });

  it.each(['mcp__screen__type', 'mcp__other__paste', 'mcp__other__press_keys'])('keeps clicks gated after forwarded input from %s, across snapshots and prompts', tool => {
    const s = setup(); s.post(tool, tool.endsWith('press_keys') ? { keys: 'cmd+v' } : { text: 'draft' }); s.view(); s.prompt();
    expect(s.state().guiInputSeen).toBe(true); expect(s.pre()).toBe('ask');
  });

  it('records forwarded typing as pending input and never treats a refused attempt as executed input', () => {
    const s = setup(); s.view(snapshot(9)); expect(s.pre(type.tool, { text: 'status' })).toBe('ask');
    s.post(type.tool, { text: 'status' }); s.view(); expect(s.pre()).toBe('ask');
    const refused = setup(); refused.view(); expect(refused.pre(type.tool, { text: 'status' })).toBe('ask');
    refused.view(); expect(refused.pre()).toBe('ask');
  });

  it('keeps every screen server gated across forwarded acknowledgments', () => {
    const s = setup({ gui: gui([click, { ...click, tool: 'mcp__other__click' }]) }); s.view(snapshot(), 'mcp__other__screenshot'); s.view();
    expect(s.pre()).toBe('ask'); expect(s.pre('mcp__other__click')).toBe('ask');
    s.view(); s.post('mcp__other__click', { index: 99 }); expect(s.pre()).toBe('ask');
    s.view(); s.post('mcp__screen__press_keys', { keys: 'cmd+c' }); s.view(); expect(s.pre()).toBe('ask');
  });

  it('never turns deny or audit into silent policy authorization', () => {
    const strict = setup({ gui: gui() }, { WARDEN_FLOW_MODE: 'deny' }); strict.view(); expect(strict.pre()).toBe('deny');
    const audit = setup({ gui: gui() }, { WARDEN_FLOW_MODE: 'audit' }); audit.view(); expect(audit.pre()).toBeUndefined();
    expect(audit.logs().filter(e => e.event === 'pre').at(-1)).toMatchObject({ reason: 'screen_action', disposition: 'audit_only' });
    expect(audit.state().screens?.screen?.policyConsumed).toBeUndefined();
  });

  it('does not reserve policy permissions in the proxy audit-only presentation either', () => {
    const s = setup(); s.view();
    expect(flowPre({ session_id: 'gui-policy', tool_name: click.tool, tool_input: { index: 3 } }, s.env, 'audit')?.permissionDecision).toBe('ask');
    expect(s.state().screens?.screen?.policyConsumed).toBeUndefined();
    expect(s.logs().at(-1)).toMatchObject({ disposition: 'audit_only', reason: 'screen_action' });
    expect(s.pre()).toBe('ask');
  });
});

describe('GUI policy configuration validation', () => {
  it.each([
    null, [], { mode: 'automatic', allow: [click] }, { mode: 'policy' }, { ...gui(), maxSnapshotAgeMs: 0 },
    { ...gui(), maxSnapshotAgeMs: 30_001 }, { ...gui(), maxSnapshotAgeMs: '5000' }, { ...gui(), typo: true },
    gui([{ ...click, tool: 'mcp__*__click' }]), gui([{ ...click, target: {} }]), gui([{ ...click, context: {} }]),
    gui([{ ...click, context: { origin: 'https://mail.example/path' } }]), gui([{ ...click, context: { origin: 'https://user:pass@mail.example' } }]),
    gui([{ ...click, context: { origin: 'file:///tmp/mail' } }]), gui([{ ...click, target: { ...click.target, extra: true } }]),
    gui([{ ...click, target: { ...click.target, accessibilityId: '' } }]), gui([{ ...click, target: { ...click.target, accessibilityId: 'x'.repeat(201) } }]),
    gui([{ ...key, keys: 'Enter' }]), gui([{ ...key, keys: 'ctrl+v' }]), gui([{ ...key, keys: undefined }]),
    gui([{ ...key, keys: ['Tab'] }]), gui([{ ...click, action: { toString: 'click' } }]),
    gui([{ ...type, maxTextLength: undefined }]), gui([{ ...type, maxTextLength: 4097 }]), gui([{ ...click, maxTextLength: 10 }]),
    gui([click, { ...click, action: 'paste' }]), gui(Array.from({ length: 65 }, () => click)),
  ])('fails closed to strict for malformed GUI policy %j', config => {
    const s = setup({ gui: config }); s.view(); expect(loadPolicy(s.env).gui?.mode).toBe('strict'); expect(s.pre()).toBe('ask');
    expect(s.reason()).toContain('Invalid GUI policy: strict behavior is active');
  });
});
