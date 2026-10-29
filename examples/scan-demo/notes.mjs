#!/usr/bin/env node
// A minimal, benign MCP server over stdio (newline-delimited JSON-RPC), for `warden-mcp scan`.
// One tool, an honest description. Nothing is written anywhere: `tools/call` answers with text only.
import { serve } from './stdio-server.mjs';

serve({
  name: 'notes',
  version: '1.0.0',
  tools: [
    {
      name: 'save_note',
      description: 'Save a short note to the local notebook and return its id.',
      inputSchema: {
        type: 'object',
        properties: { text: { type: 'string', description: 'The note, plain text, up to 2,000 characters.' } },
        required: ['text'],
        additionalProperties: false,
      },
    },
  ],
});
