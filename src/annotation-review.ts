/** Server-authored MCP annotations can request caution, never establish authority. */
import { globMatch } from './flow-guard-policy.js';
import type { FlowPolicy } from './flow-guard-types.js';
import { pinToolsHash, serverIdentityHash } from './pinning.js';
import { boundCapabilities } from './toxic-flow.js';
import type { CapabilityBinding, McpServerRef, ToolDef } from './types.js';

const HINTS = ['readOnlyHint', 'destructiveHint', 'openWorldHint'] as const;

export interface AnnotationReview {
  /** Acknowledgement is valid only inside this wrapper for this exact identity/tool set. */
  key: string;
  reason: string;
}

/** Deliberately independent of tool arguments, destination allowlists and server titles. */
export function annotationReview(
  server: McpServerRef, tools: ToolDef[], toolName: string, flowName: string,
  policy: FlowPolicy, bindings: readonly CapabilityBinding[] = [],
): AnnotationReview | undefined {
  if (!flowName || policy.annotationReview !== 'first-use' || policy.mode === 'off') return undefined;
  const qualified = `mcp__${flowName}__${toolName}`;
  if (Object.keys(policy.labels).some(glob => globMatch(glob, qualified))) return undefined;
  if (boundCapabilities(server, tools, bindings)) return undefined;
  const tool = tools.find(t => t.name === toolName);
  if (!tool || tool.annotations === undefined) return undefined;
  const annotations: unknown = tool.annotations;
  let claims: string[];
  if (!annotations || typeof annotations !== 'object' || Array.isArray(annotations)) claims = ['invalid annotation object'];
  else {
    const fields = annotations as Record<string, unknown>;
    claims = HINTS.filter(hint => Object.hasOwn(fields, hint))
      .map(hint => `${hint}=${typeof fields[hint] === 'boolean' ? String(fields[hint]) : 'invalid'}`);
    if (!claims.length) return undefined;
  }
  return {
    key: JSON.stringify([server.id, serverIdentityHash(server), pinToolsHash(tools), toolName]),
    reason: `The server supplied unverified MCP annotations (${claims.join(', ')}), and the operator has not labelled this tool. ` +
      'Review them before first use. Even readOnlyHint=true does not prove a call is read-only or free. ' +
      'Acceptance records this annotation review only for this exact server and tool set in this running wrapper; later calls still face every other guard.',
  };
}
