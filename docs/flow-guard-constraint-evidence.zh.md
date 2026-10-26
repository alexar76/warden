# 确定性答案证据与披露保留

[en](flow-guard-constraint-evidence.md) · [ru](flow-guard-constraint-evidence.ru.md) · [es](flow-guard-constraint-evidence.es.md) · [fr](flow-guard-constraint-evidence.fr.md) · [zh](flow-guard-constraint-evidence.zh.md)

本地候选版本 0.22.0，未发布到 npm。此前检查的 12 对答案中，4 对在 $150 上限下把 $190 记录列为合格；3 次继续生成删除了注入披露。历史答案与结果保持原样。

## 合约与信任边界

宿主可向 Stop hook 提供可选 `answer_check`，或调用导出的 `checkAnswerConstraints`。合约绑定精确答案 SHA-256、会话与正数轮次。可信宿主适配器提供用户/策略约束、记录快照、选中 ID 及明确声称合格的 ID 集。检查整个集合；来源里出现记录不等于答案声称其合格。支持有限数值 `lte`/`gte` 以及严格数值/布尔 `eq`。

缺失字段/ID 保持未知；畸形或过期合约不算通过。证据只输出位置和数值，例如 `actual 190; required <= 150`，不复述来源名称、ID、字段名、URL 或攻击引文。规则必须来自真实用户或运营策略，不能把 MCP 服务提供的合约提升为可信输入。宿主负责统一币种和单位。事实仍以来源快照为条件，不证明服务器诚实，也不授予权限。哈希不防御恶意宿主。

## Stop 与披露

登记过外部文本后，有效矛盾可在没有字面指令重叠时请求一次继续生成；原有重叠检查仍保留。Guard 在当前轮次保存凭据，即使模型删除披露，后续 hook 的 `systemMessage` 仍保留固定外部指令提示，不请求第二次继续生成。新轮次清除凭据；audit 仅观察。相同事实哈希下报告剩余矛盾；快照缺失或变化时，是否解决仍未知。合格选择可保留同一个 ID。

宿主必须显示 `systemMessage`；这里没有测试原生客户端实际呈现，也不保证模型自己的文字保留披露。

## 宿主示例

此前需已登记 prompt 和外部工具结果；`turn` 必须匹配 guard 当前轮次。明确主张由宿主提取，WARDEN 不理解任意自然语言。

```js
import { createHash } from 'node:crypto';
import { checkAnswerConstraints } from '@aimarket/warden';

const answer = 'A is selected. A and C are eligible.';
const answer_check = {
  schema: 'warden-answer-check/1', sessionId: 'session-1', turn: 1,
  answerSha256: createHash('sha256').update(answer).digest('hex'),
  rules: [{ field: 'priceUsd', op: 'lte', value: 150 }],
  records: [
    { id: 'A', attributes: { priceUsd: 123 } },
    { id: 'C', attributes: { priceUsd: 190 } },
  ],
  claims: { selectedId: 'A', eligibleIds: ['A', 'C'] },
};
const evidence = checkAnswerConstraints(answer_check, answer, 'session-1', 1);
// evidence.violations: [{ item: 2, rule: 1, op: 'lte', limit: 150, actual: 190 }]
// Stop input: { session_id: 'session-1', last_assistant_message: answer, answer_check }
```

## 范围

研究适配器 `scripts/selection-probe/constraint_claims.py` 只识别合成酒店 JSON 答案里的封闭英文合格列表语法。不使用语义金标，排除标准警告后缀，拒绝不支持的列表，其余文字标为未检查。它不核验所有价格主张，也不从任意文字提取数字约束。普通原生 Stop 输入不会自动产生此合约。

## Linux 验证 — 2026 年 10 月 26 日

构建和类型检查通过；**21 个文件中的 743 项 WARDEN 测试**（含 29 项新增）、**24 项 Python 工具测试**及现有 **28 场景确定性 gate** 均通过。核验全部 276 个输出哈希。运行时测试无网络，只有 npm 依赖安装联网。远端临时目录已删除。确认冻结源文件一致后，从 Linux 生成产物同步本地构建和插件。

| 保存答案上的观察 | 结果 |
| --- | ---: |
| 重放真实初始/最终答案对 | 12 |
| 在 $150 上限下声称 $190 项合格的错误集合 | 4 |
| 未改动旧最终答案中仍存在的矛盾 | 4 |
| 继续生成后 hook 输出保留 guard 指令提示 | 12/12 |
| 原先模型文字披露丢失、现在伴随 guard 提示 | 3/3 |
| 请求第二次继续生成 / 新增模型调用 | 0 / 0 |

适配器语法在阅读这些答案后编写：这是**开发案例的事后重放**，不是独立语义验证或留出集。运行时提取不读取金标，之后再与先前审查比较。发现 4 个矛盾不代表全文正确，也不估计一般误报率。4 个错误解释没有重新生成或被纠正；3 个模型文本仍缺少披露。新增保障是独立 hook 提示，其客户端实际显示仍需验证。模型纠错和独立泛化有效性均未测量。

开发和审查使用 AI 辅助；不声称独立盲法语义评审。

[results.json](data/launchgate-constraint-evidence-2026-10-26/results.json), [cases.json](data/launchgate-constraint-evidence-2026-10-26/cases.json), [execution.json](data/launchgate-constraint-evidence-2026-10-26/execution.json), [input-manifest.json](data/launchgate-constraint-evidence-2026-10-26/input-manifest.json), [manifest.json](data/launchgate-constraint-evidence-2026-10-26/manifest.json).

<!-- fresh-recheck-results -->

[模型新一轮复查：具体事实与披露](flow-guard-fresh-rechecks-2026-10-26.zh.md).

<!-- factorial-review-followup -->

[记录引用与纠错命令：四条件模型测试](flow-guard-review-factors-2026-10-26.zh.md).

<!-- structured-answer-gate -->

[应用答案门禁](flow-guard-answer-gate.zh.md)：全部规则、有界额外纠正与缓冲交付；仅支持结构化数据。
