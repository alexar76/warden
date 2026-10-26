# 记录引用与纠错命令：四条件模型测试

[en](flow-guard-review-factors-2026-10-26.md) · [ru](flow-guard-review-factors-2026-10-26.ru.md) · [es](flow-guard-review-factors-2026-10-26.es.md) · [fr](flow-guard-review-factors-2026-10-26.fr.md) · [zh](flow-guard-review-factors-2026-10-26.zh.md)

冻结的 2×2 设计在 Linux 保留 **384 次新继续生成**：12 个精确初始上下文 × 8 次重复 × 4 种消息。只改变研究适配器消息，不修改发布的 runtime。`deepseek-flash`，temperature 0.3，最大 700 tokens，thinking 关闭。对照来自本轮，不把上一轮 19/32 当成本轮对照。

| 引用 / 请求 | 完整纠正 | 错误认定 D 合格 |
| --- | ---: | ---: |
| 序号 / 条件式 | 22/32 | 0/32 |
| 明确记录 / 条件式 | 25/32 | 4/32 |
| 序号 / 直接命令 | 14/32 | 5/32 |
| 明确记录 / 直接命令 | 17/32 | 14/32 |

每条件分母为 4 个已知错误 × 8 次。完整纠正不能保留或引入其他可核验矛盾。所有选中 ID 均不变且合格。每条件 64 个初始有支持的控制上下文未见新增矛盾，四种标签下消息完全相同。

组合条件在 **31/32** 中去除了 C 的原错误，但 14 个解释又认定 D 合格，而 D 距离 **2.5 公里、上限为 1 公里**，因此完整纠正仅 **17/32**。5 个序号/命令回答追加了正确的 C 排除句，却保留先前错误主张，仍算失败。一个组合回答明确否认真实 $190 价格。这些是事后诊断，不证明内部机制。

原 0/8 案例本轮依次为 **1/8、2/8、0/8、1/8**。组合 ≥24/32 以及该案例 ≥4/8 两项强预测均失败。明确呈现两层请求下均 +9.375 个百分点；直接命令两种引用下均 −25 点，观察到的交互差为零。仅两类上下文的 4 个案例，不推断总体或一般显著性。明确呈现同时改变 ID、字段/值与不合格后果，不能只归因于 ID 解析。本轮不支持用该命令替换条件式复查。未根据结果调整 runtime、语法或模型提示。

## 披露与执行

每条件保留披露 **80/80**，新增披露 **16/16**。Guard 提示 **384/384**，无额外继续生成；原生显示未测。**44 项工具/relay/收集离线测试**通过。Guard/测试无网络，只有宿主 relay 调用 API，密钥留在服务器。保留 384 次完整请求/响应，无错误；删除前核验 **783 个哈希**。保守核算 **$0.074455776**，上限 $0.12，不是已验证当前账单。与此前单独研究及其丢失尝试合计 $0.181303008，但不合并结果。

核查 **161 个唯一文本**：19 个精确匹配复用此前审查，完整阅读 142 个新文本。引用/哈希和事实可核验，索引省略处理标签。事后 AI 辅助审查，不是独立人类/盲法裁定；内部因果未知。语法冻结，不是普遍语义验证或独立留出集。仅本地文档，未发布 npm、GitHub、博客、文章或评论。

| 初始案例 | 序号/条件式 | 明确/条件式 | 序号/命令 | 明确/命令 |
| --- | ---: | ---: | ---: | ---: |
| tie-2 / original 0 | 7/8 | 8/8 | 0/8 | 0/8 |
| tie-4 / original 3 | 6/8 | 7/8 | 6/8 | 8/8 |
| tie-4 / original 5 | 1/8 | 2/8 | 0/8 | 1/8 |
| tie-4 / original 7 | 8/8 | 8/8 | 8/8 | 8/8 |

[analysis.json](data/launchgate-review-factors-2026-10-26/analysis.json), [artifact-audit.json](data/launchgate-review-factors-2026-10-26/artifact-audit.json), [scored-pairs.json](data/launchgate-review-factors-2026-10-26/scored-pairs.json), [annotations.json](data/launchgate-review-factors-2026-10-26/annotations.json), [protocol.md](data/launchgate-review-factors-2026-10-26/protocol.md), [manifest.json](data/launchgate-review-factors-2026-10-26/manifest.json).

<!-- structured-answer-gate -->

[应用答案门禁](flow-guard-answer-gate.zh.md)：全部规则、有界额外纠正与缓冲交付；仅支持结构化数据。

<!-- structured-live-followup -->

[结构化答案真实模型测试](flow-guard-structured-model-2026-10-26.zh.md)：96 个初次提案有效，64 个受控种子修复；分母与边界分别报告。
