# Warden 0.7.0: approvals and continuous verification

> 🌐 **English** · [Русский](security-hardening.ru.md) · [Español](security-hardening.es.md) · [Français](security-hardening.fr.md) · [中文](security-hardening.zh.md)

Warden 0.7.0 and ARGUS 0.3.2 close six gaps. This is a definition and launch-configuration firewall, not an operating-system sandbox or a guarantee about server behaviour.

1. **Before connection.** Call `warden.vetLaunch(server)` before spawning a stdio process or opening a remote transport. It checks origin, known command/endpoint threats and the pinned launch identity. Once connected, obtain the complete `tools/list` and call `vet(server, tools)` before exposing tools. A successful launch check alone does not approve tools.
2. **Signed feed rollback.** The last accepted timestamp, content digest and records are stored per publisher key under `feeds/`. An older timestamp, or different content with the same timestamp, is rejected even after restart. A newer signed snapshot can intentionally remove a rule. Failed updates retain the last-good records; `feed.status.stale` reports freshness separately, so retained rules are not presented as current intelligence. The ten-second deadline covers headers and the complete body. The byte and record caps still apply.
3. **Stdio.** Invalid JSON-RPC envelopes return `-32600`, invalid parameters return `-32602`, and syntax errors return `-32700`. UTF-8 is decoded only after a complete frame arrives. Frames are limited to 1 MiB; legacy Content-Length headers to 8 KiB. Oversized or invalid framing terminates the connection deliberately; invalid request objects do not. The separate tool-argument limit remains 256,000 characters.
4. **Durable approvals.** `vet_mcp_server` reads persisted pins. `status_mcp_server({server, tools})` returns `previous`, `previousRevision`, `currentTools`, `currentToolsHash`, `currentIdentityHash` and `changed` for review. Approval requires the exact reviewed tool and identity hashes and `previous_pin_revision` (null for first approval). Revocation also requires the previous revision. Concurrent changes invalidate a stale review. Definitions are retained for comparison; never put live credentials in them.
5. **Complete definitions.** Hash format v2 pins all advertised fields, including `title`, `outputSchema`, `annotations` and extension metadata. Undefined top-level fields are omitted. Plain name/description/inputSchema payloads keep their existing digest. Legacy pins that did not cover extended fields require explicit reapproval (`PIN_FORMAT_UPGRADE_REQUIRED`); new pins record `toolsHashVersion: 2`. Ruleset v6 scans these additional surfaces. JSON delimiters around a schema description are not treated as evidence that an instruction is merely a quotation. Annotations remain untrusted hints and grant no permissions.
6. **During the session.** ARGUS quarantines tools immediately on `notifications/tools/list_changed` and rechecks all pages. It also rechecks before every tool call, including when a server sends no notification. Old wrappers are tied to the definitions the user/model saw and cannot execute a changed definition after reapproval. Listing failures, duplicate names, repeated cursors, over 32 pages, over 256 tools or over 1 MiB of listed definitions fail closed. Drift is never automatically reapproved. Initial clean connections retain ARGUS's existing automatic first-pin policy; this is not a human review step. Pin-write failure now closes the connection. A change during execution withholds the result, but cannot undo an already performed side effect; do not retry automatically.

## State and operator permissions

The state directory is `WARDEN_STATE_DIR`, otherwise `$XDG_STATE_HOME/warden`, otherwise `~/.local/state/warden`. A library caller can supply `ThreatFeed({stateDir})` or `FilePinStore(directory)`. ARGUS stores feed state below its configured memory directory (`warden/`). Pin files use hashed server IDs, atomic replacement and owner-only permissions; writes use per-file locks. If a process dies while holding a lock, later mutation fails closed. Stop all writers, inspect the state and remove only the abandoned `.lock` file; do not delete snapshots to silence an error. Keep the directory on a persistent local volume. Deleting it discards approvals and rollback history.

By default MCP approval mutations are disabled. The operator may set `WARDEN_ALLOW_PIN_CHANGES=1` **before starting** `warden-mcp`. This delegates approval/revocation capability to that MCP client; a request argument cannot enable it. Human review must be enforced by the host or by using a separate operator session. Scanning never approves silently, and reapproval must still pass the other security gates.

## Upgrade and limits

Publish/install `@aimarket/warden@0.7.0` first, then `@alexar76/argus3@0.3.2`, which pins that dependency. Restart MCP clients. Review legacy-pin migration findings rather than deleting pins. Other hosts must wire `vetLaunch` and runtime revalidation themselves. Neither hash comparisons nor notifications detect a backend changing its behaviour while advertising identical definitions. Tool results remain untrusted; these changes do not implement result-content screening or process isolation. Added local regression tests cover rollback/restart, body timeout, split UTF-8, invalid messages, approval persistence, metadata drift and ARGUS call blocking. No paid calls or production deployment are required to run them.

```js
const state = (await client.callTool({
  name: "status_mcp_server", arguments: { server, tools },
})).structuredContent;
// Review state.previous against state.currentTools and the launch identity first.
await client.callTool({ name: "approve_mcp_server", arguments: {
  server, tools,
  reviewed_tools_hash: state.currentToolsHash,
  reviewed_identity_hash: state.currentIdentityHash,
  previous_pin_revision: state.previousRevision,
} });
const verdict = (await client.callTool({
  name: "vet_mcp_server", arguments: { server, tools },
})).structuredContent;
if (!verdict.allow) throw new Error("WARDEN blocked the server");
// Revoke using a freshly reviewed status, not the pre-approval revision.
```
