# MCP registries — WARDEN

| Registry | Status | How |
|----------|--------|-----|
| **Glama** | Submitted / indexing | [`glama.json`](../glama.json), [`GLAMA.md`](GLAMA.md) |
| **Official MCP Registry** | Publish via CI / CLI | [`server.json`](../server.json) → `io.github.alexar76/warden` · workflow [`publish-mcp-registry.yml`](../.github/workflows/publish-mcp-registry.yml) · monorepo `./scripts/publish_mcp_registry.sh` |
| **Smithery** | Config in repo | [`smithery.yaml`](../smithery.yaml) — connect `alexar76/warden` in [smithery.ai](https://smithery.ai) after mirror |
| **mcp.so** | Manual form | Repo `https://github.com/alexar76/warden`, npm `@aimarket/warden`, tags: mcp, security, firewall |
| **PulseMCP** | Manual / ingest | Prefer Official Registry first — Pulse often ingests from it; else [pulsemcp.com](https://pulsemcp.com) submit |

## Official Registry (copy-paste)

```bash
# 1) npm must advertise mcpName (package.json field) at the version in server.json:
NPM_TOKEN=… ./scripts/publish_warden.sh   # publishes @aimarket/warden@0.5.0

# 2) From monorepo root:
./scripts/publish_mcp_registry.sh --validate-only
./scripts/publish_all_repos.sh --satellite warden

# 3) Publish to registry.modelcontextprotocol.io (pick one):
mcp-publisher login github                 # as alexar76
./scripts/publish_mcp_registry.sh --publish --only warden
# or, after GH_PAT has `workflow` scope so the Actions file can mirror:
./scripts/publish_mcp_registry.sh --dispatch

./scripts/publish_mcp_registry.sh --check-live
```

Ownership proof: `"mcpName": "io.github.alexar76/warden"` in **published** `package.json` + `<!-- mcp-name: io.github.alexar76/warden -->` in README.

Note: the monorepo keeps `.github/workflows/publish-mcp-registry.yml`; the GitHub satellite mirror currently excludes it until `GH_PAT` includes the `workflow` scope.

## mcp.so / Pulse submit blurb

> WARDEN — stdio MCP security firewall. Vets advertised tool definitions (static-scan → threat-feed → origin → pinning) before they reach the model. Tools: `vet_mcp_server`, `static_scan_tools`, `classify_sensitive_tools`, `check_egress_url`, `canonicalize_json`, `list_scan_rules`. Zero npm runtime dependencies. `npx -y @aimarket/warden`
