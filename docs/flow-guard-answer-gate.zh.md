# 由应用拥有的结构化答案门禁

[en](flow-guard-answer-gate.md) · [ru](flow-guard-answer-gate.ru.md) · [es](flow-guard-answer-gate.es.md) · [fr](flow-guard-answer-gate.fr.md) · [zh](flow-guard-answer-gate.zh.md)

本地候选版本 **0.22.0**，2026 年 10 月 26 日；尚未发布 npm。这是[四条件继续回答实验](flow-guard-review-factors-2026-10-26.zh.md)的后续：去掉 C 的价格错误，有时会引入 D 的距离错误。消除一个矛盾并不等于完整纠正。

## 契约与验证范围

`createAnswerGate` 从 `@aimarket/warden` 导出，须由应用明确接入。应用拥有用户／策略规则、规范化记录快照、会话／轮次、模型调用和最终显示，并在验证前缓冲候选答案。外部服务器的指令不能成为规则来源。

目录用安全的 `rec-…` 和 `field_1` 替换原始 ID、字段名。反馈包含明确记录、字段、实际值和要求边界，不复制来源名称、URL 或指令片段。`referenceForRecord(sourceId)` 是供应用使用的映射。SHA-256 绑定会话、轮次、完整快照、规则与可选排序；记录重排不改变引用。

模型只能返回四个字段：`schema: "warden-selection/1"`、`catalogSha256`、`selectedRef`、`eligibleRefs`。JSON 和 API 示例见[英文版](flow-guard-answer-gate.md)。

每次候选答案都重新按**全部规则检查所选记录和全部声明合格的备选记录**，并检查合格集合完整性以及可选的数值最小／最大排序。最优并列项均可接受。支持有限数值 `lte`／`gte` 和严格数值／布尔 `eq`。必要数据缺失、类型错误、过期契约、未知引用、重复 JSON 键、自由文本及多余字段都不会获准输出。没有合格记录时保留结果，不交付候选项。

输出仅包含验证后的结构化数据，其属性取自应用冻结的快照，不取自模型自由文本。此机制不验证任意解释、日期、地理信息、来源真实性或隐蔽偏好影响。应用负责单位规范化与规则选择。答案通过不代表授权支付、动作或工具调用。

## 有界纠正与输出边界

`gate.run({ generate, emit, maxCorrections: 2, timeoutMs: 30000 })` 最多执行一次初始提案和**两次纠正**，比一次纠正方案多一个有界轮次。若 C 被移除却加入 D，下一反馈指出 D 的 `2.5 > 1`。达到上限后输出 `WARDEN_RESULT_WITHHELD`，绝不交付被拒候选答案。纠正次数只能设为 0／1／2。

每个实例只预留一次运行／输出。生成失败、取消和超时均不自动重试；迟到答案不能发布。模型适配器必须遵守 `signal` 以停止自己的工作。输出投递状态不确定时不重发。应用负责跨实例请求所有权，也不能向用户流式输出未经验证的候选答案或日志。

固定告知由应用生成，不依赖模型配合。`disclosure: "source-instructions"` 仅用于已有指令检测证据的情况；默认告知使用了外部记录。应用必须实际显示告知。[可运行 stdio 示例](../examples/answer-gate-host.mjs)接收 `--contract host-owned.json`，从 stdin 逐行读提案，在 stderr 写目录／反馈，在 stdout 仅写最终已验证结果或保留通知；示例本身不调用模型、API 或工具。

**普通 Stop hook 不拥有最终显示边界。** 它仍只请求一次继续回答。要保留结果，应用须明确接入 SDK 并缓冲交付。自己的 stdio 集成测试不能证明第三方原生客户端的 GUI 已显示告知。

## 验证与结论限制

材料在单仓库的 `docs/evidence/launchgate-answer-gate-2026-10-26/`。在 Linux factory-vps 编译和测试，不新增模型调用。测试覆盖 C→D→有效结果、持续 D 错误的保留、完整集合／排序／并列、未知和过期数据、恶意元数据、取消、超时、并发、投递不确定性，以及真实子进程 stdout。

历史重放只把 384 个保留答案中明确标注的合格列表投影到新格式。不支持的自由文本仍为未知。拒绝编码后的错误列表不等于自动理解自由文本、模型重新纠错成功或独立保留集上的安全效果。原有答案与实验结果均不改写。

已完整阅读一个顽固案例的原始对话：同一回答既说 C 为 $129 且合格，又说 C 为 $190 因而不合格。这证明文本存在可观察的矛盾，不能证明内部推理原因。准备与分析使用 AI 辅助，未声称独立盲审。

<!-- verified-answer-gate-results -->

Linux factory-vps 已通过编译／类型检查、**24 个测试套件的 791 项测试**（其中 **43 项为新门禁／stdio 测试**）及原有 28 个 red-team 场景。384 个历史投影中：50 个错误显式列表被拒绝，75 个正确列表获准，259 个不支持的自由文本答案保持未知；未交付未经验证的候选答案。这是标注数据投影，不是新的模型纠正率。已校验 289 个输出文件哈希并同步 276 个 Linux 生成的本地文件。先前两次测试语法失败的记录均保留。

[results.json](data/launchgate-answer-gate-2026-10-26/results.json) · [execution.json](data/launchgate-answer-gate-2026-10-26/execution.json) · [historical-replay.json](data/launchgate-answer-gate-2026-10-26/historical-replay.json) · [stubborn-transcript.json](data/launchgate-answer-gate-2026-10-26/stubborn-transcript.json) · [manifest.json](data/launchgate-answer-gate-2026-10-26/manifest.json)

<!-- structured-live-followup -->

[结构化答案真实模型测试](flow-guard-structured-model-2026-10-26.zh.md)：96 个初次提案有效，64 个受控种子修复；分母与边界分别报告。
