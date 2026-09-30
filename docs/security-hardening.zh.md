# Warden 0.7.0：持久审批与持续验证

> 🌐 [English](security-hardening.md) · [Русский](security-hardening.ru.md) · [Español](security-hardening.es.md) · [Français](security-hardening.fr.md) · **中文**

Warden 0.7.0 和 ARGUS 0.3.2 修复六个缺口。它检查工具定义和启动配置，不是操作系统沙箱，也不保证服务器实际行为安全。

1. **连接之前。** 在启动 stdio 进程或建立远程连接前调用 `warden.vetLaunch(server)`，检查来源、已知危险命令/地址及已批准的启动身份。连接后获取完整分页 `tools/list`，再调用 `vet(server, tools)`，通过后才向模型暴露工具。启动检查通过不等于工具已获批准。
2. **签名威胁库防回滚。** 按发布者公钥在 `feeds/` 保存最后接受的 timestamp、digest 和记录。拒绝较旧时间戳，以及相同时间戳下不同的内容；重启后仍有效。更新的合法签名快照可以主动删除规则。更新失败时保留最后有效的规则；`feed.status.stale` 单独说明新鲜度，保留规则不代表它们是最新情报。十秒超时覆盖响应头和完整响应体，字节数及记录数限制继续有效。
3. **Stdio。** 错误 JSON-RPC 结构返回 `-32600`，错误参数返回 `-32602`，JSON 语法错误返回 `-32700`。收到完整帧后才解码 UTF-8。每帧最多 1 MiB，旧式 Content-Length 头最多 8 KiB。超限或损坏的帧会主动关闭连接；错误的请求对象不会结束进程。工具参数仍有独立的 256 000 字符限制。
4. **持久审批。** `vet_mcp_server` 读取已保存的指纹。`status_mcp_server({server, tools})` 返回 `previous`、`previousRevision`、`currentTools`、`currentToolsHash`、`currentIdentityHash`、`changed` 供比较。批准必须提供已审阅的准确工具哈希、启动身份哈希及 `previous_pin_revision`（首次为 null）。撤销也需要上一版本标识；并发更新会使旧审阅失效。工具定义会保存用于比较，请勿写入真实凭据。
5. **完整定义。** 指纹格式 v2 包含所有公布字段，包括 `title`、`outputSchema`、`annotations` 和扩展元数据；忽略顶层 undefined 字段。只有 name/description/inputSchema 的定义保留原 digest。未覆盖扩展字段的旧审批需要明确重新批准（`PIN_FORMAT_UPGRADE_REQUIRED`）；新记录包含 `toolsHashVersion: 2`。规则集 v6 扫描新增字段。JSON 序列化引号不再被误认为“指令只是无害引用”。注解始终是不可信提示，不授予权限。
6. **会话期间。** 收到 `notifications/tools/list_changed` 后，ARGUS 立即暂停工具并重新检查所有页面。每次工具调用前也重新检查，覆盖不发通知的服务器。旧工具引用绑定用户/模型曾看到的定义，重新批准后也不能调用已经变化的定义。列表获取失败、重名、重复游标、超过 32 页、256 个工具或 1 MiB 定义时阻止使用。变化不会自动重新批准。首次正常连接保留 ARGUS 原有的自动首次记录策略，这不表示人工审阅。记录失败现在会关闭连接。执行期间发生变化会隐藏结果，但不能撤销已发生的副作用，请勿自动重试。

## 状态存储与操作员权限

状态目录依次为 `WARDEN_STATE_DIR`、`$XDG_STATE_HOME/warden`、`~/.local/state/warden`。库调用可指定 `ThreatFeed({stateDir})` 或 `FilePinStore(directory)`。ARGUS 在配置的内存目录下使用 `warden/` 保存威胁库。审批文件名由服务器 ID 的哈希生成，采用原子替换、仅所有者权限和逐文件锁。进程持锁崩溃后，后续修改会安全失败：停止所有写入进程，检查状态，只删除遗留 `.lock`；不要删除快照来掩盖错误。使用持久本地卷。删除目录会丢失审批及防回滚历史。

MCP 默认禁止修改审批。操作员可在启动 `warden-mcp` 前设置 `WARDEN_ALLOW_PIN_CHANGES=1`。这会向该 MCP 客户端授予批准/撤销能力，请求参数不能开启它。人工审阅须由宿主或独立操作员会话落实。扫描不自动批准，重新批准仍须通过其他安全检查。

## 升级与边界

先发布/安装 `@aimarket/warden@0.7.0`，再发布/安装依赖该版本的 `@alexar76/argus3@0.3.2`，然后重启 MCP 客户端。审阅旧审批迁移提示，不要直接删除审批。其他宿主须自行接入 `vetLaunch` 和运行期间复查。定义完全相同时，哈希无法检测后端行为改变。工具结果仍是不可信数据；本次不提供结果内容过滤或进程隔离。新增本地回归测试覆盖回滚、重启、响应体超时、UTF-8 分片、非法请求、审批持久化、元数据漂移和 ARGUS 调用阻止，不需要付费调用或生产部署。

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
