# Glama listing — WARDEN

Public page (after indexing): [glama.ai/mcp/servers/alexar76/warden](https://glama.ai/mcp/servers/alexar76/warden)

Admin Dockerfile form: [glama.ai/mcp/servers/alexar76/warden/admin/dockerfile](https://glama.ai/mcp/servers/alexar76/warden/admin/dockerfile)

## What Glama actually runs

Glama **generates** its own image (debian + node, clone into `/app`, wrap CMD with `mcp-proxy --`). The repo [`Dockerfile`](../Dockerfile) is for local/self-host. After **Add MCP Server**, paste the fields below and **Sync Server**.

The health check is: container starts, answers JSON-RPC `initialize` + `tools/list` over **stdio**, no required secrets.

### Form values (copy-paste)

| Field | Value |
|-------|-------|
| **Build steps** | `["npm ci", "npm run build"]` |
| **CMD arguments** | `["node", "dist/mcp-server.js"]` — do **not** put `mcp-proxy` here; Glama wraps it |
| **Pinned commit SHA** | empty — use **`main`** (squashed satellite mirror deletes old SHAs) |
| **Environment variables** | none — WARDEN MCP needs no keys |

`glama.json` lists `maintainers: ["alexar76"]` so the GitHub account that owns the repo can **Claim** the listing.

## TDQS / AAA

Tool definitions in `src/mcp-tools.ts` are written against the [TDQS checklist](https://github.com/glama-ai/tool-definition-quality-score/#improving-your-score):

- title longer than the name, sibling-aware when-to-use / when-not
- MCP annotations (`readOnlyHint`, `destructiveHint`, `idempotentHint`, `openWorldHint`) matching behaviour (all six tools are local reads)
- every `inputSchema` property described; `outputSchema` on every tool
- no annotation/description contradictions, no required env

After the first successful build, open the **score** tab, claim the server, and wait for the sweep to grade tools. Re-sync if `tools/list` changed.

## Local Docker test

```bash
docker build -t warden-mcp .
# initialize + tools/list (NDJSON — what Glama's mcp-proxy speaks)
python3 - <<'PY' | docker run --rm -i warden-mcp
import json, sys
def send(obj):
    sys.stdout.write(json.dumps(obj) + "\n")
    sys.stdout.flush()
send({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"probe","version":"0"}}})
send({"jsonrpc":"2.0","method":"notifications/initialized"})
send({"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}})
PY
```

Or without Docker, after `npm run build`:

```bash
node dist/mcp-server.js
```

Claude Desktop / Cursor:

```json
{
  "mcpServers": {
    "warden": {
      "command": "npx",
      "args": ["-y", "@aimarket/warden"]
    }
  }
}
```
