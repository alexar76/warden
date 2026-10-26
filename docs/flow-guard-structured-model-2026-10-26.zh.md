# 结构化答案边界的真实模型测试

[en](flow-guard-structured-model-2026-10-26.md) · [ru](flow-guard-structured-model-2026-10-26.ru.md) · [es](flow-guard-structured-model-2026-10-26.es.md) · [fr](flow-guard-structured-model-2026-10-26.fr.md) · [zh](flow-guard-structured-model-2026-10-26.zh.md)

2026 年 10 月 26 日。本地 WARDEN **0.22.0**，运行时代码未改，未发布 npm。这是[应用答案门禁](flow-guard-answer-gate.zh.md)及[四条件实验](flow-guard-review-factors-2026-10-26.zh.md)的后续。

## 设计与结果

在 Linux factory-vps 对 `deepseek-flash` 发起 160 次新调用：temperature .3、关闭 thinking、JSON object mode、最多 700 输出 token。真实且冻结的 `createAnswerGate` 检查全部规则、完整合格集合与最低价格。没有暗中修改模型候选答案来获得通过。

保留十二段原始上下文，包括外部指令和原有自由文本答案。新增用户请求要求使用规范化目录与四字段契约完整替换旧答案。每段重复八次，共 **96/96 个初次提案有效**，其中来自四个旧矛盾上下文的 **32/32** 也有效；其余八段原解释有事实支持。因此，自然产生的纠正机会为零。

另设独立受控组：实验者构造真正合格集合加 C（价格 190 > 150）或 D（距离 2.5 > 1）的错误列表。它们是**合成初始错误**，并非模型新产生的失败。四段上下文、每类八次，**32/32 个 C 错误及 32/32 个 D 错误均在首次真实纠正调用后修复**。合成种子占 SDK 初次提案，之后最多两次纠正；不能把这一组的纠正率与自然初次提案正确率混合。

160 个新答案均未把 C/D 放入合格列表，也没有重复 JSON 键、无效格式或额外自由文本字段。捕获 **160 个已检查结果和 160 个应用告知**，没有未经验证的候选交付、API 错误、C→D 替换或丢弃的尝试。冻结预测均达到：自然初次正确 >=80/96，受控最终正确 >=48/64。

**所有轨迹只需一次真实调用，均未触发第二次纠正或保留。** 本次不提供这些路径的真实模型成功率；此前确定性／stdio 测试仍用于证明机制行为。

在测量的结构化表面上，没有出现保留旧错误再追加新说法的现象。模式只有一个合格列表，没有模型自写价格、排除结论或解释字段。输出契约、目录和指令同时改变，因此不能把效果单独归因于格式；没有同期自由文本对照或独立保留集。十二段已知上下文的重复满分不是通用可靠性保证或广泛注入防护证明。

## 审核、费用与边界

收集后按原始事实重新计算全部最终值，审核过程不调用运行时验证器。测量的是捕获的最终输出帧，不是第三方原生 GUI 的实际显示。来源真实性、任意解释、支付／动作权限，以及并列项之间的隐蔽偏好影响都不在本结论内。

付费调用前，Linux 上通过 **9 项 Node 适配器测试、28 项 relay／预算／收集测试**及 480 个请求预检。容器无网络、无密钥；只有主机 relay 可访问固定官方 API。完整请求与响应均保留，删除临时目录前校验 **333 个输出哈希**。没有传输自动重试或重复实验；无需修改运行时代码。

全部调用在非高峰时段。Usage：输入 211,200 token，其中缓存 103,936；输出 17,946。按[公布费率](https://api-docs.deepseek.com/quick_start/pricing/)计算 **USD 0.027169008**；保守高峰计费 **USD 0.054338016**，低于 **USD 0.15** 硬上限。未核查发票或账户余额差额；使用现有服务器。

准备与审核由 AI 辅助、非盲审；未声称独立人工审核。没有 GitHub／npm 发布，也未发送评论。

[analysis.json](data/launchgate-structured-model-2026-10-26/analysis.json) · [protocol.md](data/launchgate-structured-model-2026-10-26/protocol.md) · [execution.json](data/launchgate-structured-model-2026-10-26/execution.json) · [output-audit.json](data/launchgate-structured-model-2026-10-26/output-audit.json) · [trajectories.jsonl](data/launchgate-structured-model-2026-10-26/trajectories.jsonl) · [manifest.json](data/launchgate-structured-model-2026-10-26/manifest.json)

<!-- prospective-holdout-followup -->

[冻结后的新案例](flow-guard-prospective-holdout-2026-10-26.zh.md)：自然初次有效 89/96，七个错误中五个纠正、两个保留；受控纠正 45/48。后续排序／缺失集合证据已离线验证，未重新调用模型。
