# 数值反馈的最终真实比较

[en](flow-guard-final-witness-2026-10-26.md) · [ru](flow-guard-final-witness-2026-10-26.ru.md) · [es](flow-guard-final-witness-2026-10-26.es.md) · [fr](flow-guard-final-witness-2026-10-26.fr.md) · [zh](flow-guard-final-witness-2026-10-26.zh.md)

2026 年 10 月 26 日。**系列已完成。** 本地 WARDEN 0.22.0 代码未变，已有 798 项测试验证。API 前冻结预测、两版 SDK、队列、消息与顺序。

包含此前全部五个真实保留上下文：两个来自自然错误、三个来自受控起点，跨四个 fixture。每例八个配对区块，对比旧判定与所选／最优数值及达到最优的引用。历史、目录、错误答案完全相同，仅最后复查消息改变。两组目录原本都有这些数字。

| 组别 | 旧反馈 | 数值证据 |
|---|---|---|
| 已知错误的继续回答 | **6/40 有效**，34 个保留 | **40/40 有效** |
| 构造的正确答案对照 | **20/20 保持有效** | **20/20 保持有效** |

配对结果：34 个仅证据组成功，6 个均成功；没有仅旧组成功或两组都失败。此固定队列差 85 个百分点，每个上下文证据组均 8/8。自然来源 5/16 对16/16，受控来源 1/24 对24/24。预测 >=32/40、改善 >=8/40、对照 >=19/20 全部达到。正确对照两组消息相同，只测保持能力。

86 个交付帧均通过算术审核，34 个旧组错误输出被保留；120 帧全部有主机告知。无 API 错误、丢弃、自动重试或重复研究。这是从已保留答案开始的一次独立研究继续回答，不是产品第三次纠正；产品最多两次纠正不变。

结论限于完整反馈消息在选定已知错误上的效果，不是独立保留集、通用可靠性、缺失集合提示效果或内部原因。AI 辅助同一作者、非盲审；未测第三方原生 GUI。不能分离单句效果或断定此前信息不足。旧冻结结果不改写。

API 前 Linux 通过 8 项研究测试、28 项 relay／预算／收集测试及 120 项预检。Runner 无网络／密钥，仅主机 relay 访问官方端点。完整交互保留，删除前校验 **253 个哈希**。

120 次非高峰调用按 usage 为 **USD .012380472**，保守高峰 **USD .024760944**。加前一项前瞻实验为 **USD .041314905** 按时段／**USD .082629810** 保守，低于 .15。未查发票／余额，使用现有服务器。没有 GitHub／npm 发布或发送评论；本系列不再增加模型实验。

[analysis.json](data/launchgate-final-witness-2026-10-26/analysis.json) · [protocol.md](data/launchgate-final-witness-2026-10-26/protocol.md) · [freeze.json](data/launchgate-final-witness-2026-10-26/freeze.json) · [execution.json](data/launchgate-final-witness-2026-10-26/execution.json) · [trajectories.jsonl](data/launchgate-final-witness-2026-10-26/trajectories.jsonl) · [manifest.json](data/launchgate-final-witness-2026-10-26/manifest.json)
