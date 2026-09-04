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
# From monorepo root (after npm has @aimarket/warden@0.5.0 with mcpName):
./scripts/publish_mcp_registry.sh --validate-only
./scripts/publish_all_repos.sh --satellite warden
./scripts/publish_mcp_registry.sh --dispatch   # or --publish --only warden
./scripts/publish_mcp_registry.sh --check-live
```

Ownership proof: `"mcpName": "io.github.alexar76/warden"` in published `package.json` + `<!-- mcp-name: io.github.alexar76/warden -->` in README.

## mcp.so / Pulse submit blurb

> WARDEN — stdio MCP security firewall. Vets advertised tool definitions (static-scan → threat-feed → origin → pinning) before they reach the model. Tools: `vet_mcp_server`, `static_scan_tools`, `classify_sensitive_tools`, `check_egress_url`, `canonicalize_json`, `list_scan_rules`. Zero npm runtime dependencies. `npx -y @aimarket/warden`
