# WARDEN for Claude Code

A Claude Code plugin that vets the MCP servers your project starts before the model sees their tools.

```text
/plugin marketplace add alexar76/warden
/plugin install warden@warden
```

| Hook | What it does |
|---|---|
| `SessionStart` | Runs `warden-mcp scan` over the servers in `.mcp.json` and in your `~/.claude.json` (user scope and this project). Tells you and the model which servers or tools are blocked, by name and finding code only — a blocked description is never put into the model's context. Uses `warden.lock.json` from the project root when it exists. |
| `PreToolUse` on `mcp__.*` | Denies a call to a tool whose server or tool the session-start scan blocked. Reads one small file; starts nothing. |

It also adds the skill `/warden:scan`, which runs the scan and explains the result.

## Limits

- The check happens at session start. A server that changes its tools later in the session is not re-checked; run it behind [`warden-mcp wrap`](https://github.com/alexar76/warden#protect-claude-desktop-or-cursor-with-one-wrapper) for that.
- Servers that other plugins or claude.ai connectors provide are not in these files, so WARDEN does not vet them and makes no decision on their calls. Set `WARDEN_HOOK_STRICT=1` to be asked instead.
- Scanning starts each stdio server once, as Claude Code itself does. Set `WARDEN_HOOK_NO_LAUNCH=1` to vet launch lines only.
- The first session downloads `@aimarket/warden` through `npx`; later sessions use the npm cache.

Environment: `WARDEN_STATE_DIR` (where verdicts live), `WARDEN_HOOK_TIMEOUT_MS` (per server, default 20000), `WARDEN_HOOK_STRICT`, `WARDEN_HOOK_NO_LAUNCH`.

Opt-in classifier: set `WARDEN_CLASSIFIER_URL` (an OpenAI-compatible endpoint, for example a local Ollama at `http://localhost:11434/v1`) and `WARDEN_CLASSIFIER_MODEL`; a key, if needed, in `WARDEN_CLASSIFIER_API_KEY`. Tool definitions are then sent to that endpoint at session start. Its verdicts are advisory unless `WARDEN_CLASSIFIER_BLOCKS=1`. See [the scan guide](../docs/scan.md#the-optional-classifier).
