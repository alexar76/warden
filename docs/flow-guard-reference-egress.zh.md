# 纯引用式外发：已验证行为与限制

[en](flow-guard-reference-egress.md) · [ru](flow-guard-reference-egress.ru.md) · [es](flow-guard-reference-egress.es.md) · [fr](flow-guard-reference-egress.fr.md) · [zh](flow-guard-reference-egress.zh.md)

2026年10月26日。本地 WARDEN **0.22.1**。在 Linux factory-vps 上完成构建、类型检查及四套测试，**127/127 通过，其中25项为新增测试**。本次无需修改运行时代码、强匹配阈值或版本。无付费模型调用，无真实外发操作，新增 API 费用为0。

## 验证内容

手写的“使用那张表的第三条记录”等表达不含已读取密钥的指纹匹配。在已观察到凭据读取和外部文本的会话中，外发调用仍需 `ask` 审核，`deny` 模式则拒绝。经过1/3/8个已观察到的中间工具结果以及新的用户轮次后，该边界仍然有效。用户指定或策略允许的收件人本身不能豁免。无明显发送含义的 MCP 工具名也会检查；非 MCP 工具需要显式 `outbound` 分类。

这是会话／动作边界，**并非语义来源追踪**。转换文本由人工编写，未调用模型生成，测试也未执行真实发送工具。既有 Stop 测试仍记录无字面重叠的改写缺口。

## 例外与限制

操作者对完整工具名和参数的精确授权可让这种不透明引用**通过一次**；这不证明被引用内容是公开数据。重复请求、修改正文／收件人／嵌套参数／工具，或 host 禁止公开请求授权时，仍需审核。即使存在精确授权，已知密钥的字面匹配仍被拒绝。

没有显式标签的未知非 MCP 工具不在此边界覆盖内。未观察到凭据或外部文本时，不启用此凭据边界。无可识别凭据的一般私有数据并非普遍受此规则保护。`audit` 仅记录，`off` 关闭检查。Host 必须运行 hooks 并执行判定。本次没有重测独立 task-adapter 执行器或原生界面显示。

强窗口保持 **非hex为8、hex为10**；既有独立短片段测试通过。不能据此宣称普遍防止语义泄露。

## 证据

自动审核最初拒绝导出后，用户明确授权将101个文件／316 KB发送到 factory-vps。无密钥或服务器配置，仅安装开发依赖时联网且禁用脚本；运行检查的非特权只读容器无网络。收集后验证6个输出哈希，再删除远程临时目录。AI协助准备测试与报告；未向GitHub/npm写入或发布评论。

[Results](data/qingfeng-reference-egress-2026-10-26/results.json) · [Protocol](data/qingfeng-reference-egress-2026-10-26/protocol.md) · [Execution](data/qingfeng-reference-egress-2026-10-26/execution.json) · [Tests](data/qingfeng-reference-egress-2026-10-26/vitest.json) · [Input hashes](data/qingfeng-reference-egress-2026-10-26/input-manifest.json).
