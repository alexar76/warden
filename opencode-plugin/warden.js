// WARDEN flow guard for OpenCode: copy this file into OpenCode's plugin folder (~/.config/opencode/plugin/ or
// .opencode/plugin/), and dist/opencode-plugin.js with every dist/flow-guard*.js into ~/.config/opencode/warden/.
// Export only the plugin: OpenCode calls every exported function as one. See docs/opencode.md.
import { createWardenPlugin } from '../warden/opencode-plugin.js';

export const WardenFlowGuard = createWardenPlugin({
  block: 'data',
  // Keys only the OpenCode process needs; shell commands get them blank. Add your provider's.
  stripEnv: ['DEEPSEEK_API_KEY', 'OPENAI_API_KEY', 'ANTHROPIC_API_KEY'],
});
