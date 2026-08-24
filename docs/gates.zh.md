# 门控链

> 🌐 [English](gates.md) · [Русский](gates.ru.md) · [Español](gates.es.md) · [Français](gates.fr.md) · **中文**

`Warden.vet(server, tools)` 会按顺序跑完一条门控链，并返回单一裁定。本页就是完整的判定过程：每个门控看什么、
它可以阻止什么，以及最后那个数字是怎么算出来的。

```
static-scan  →  threat-feed  →  origin  →  pinning
 （免费）        （load 之后     （免费）    （免费）
                  免费）
```

顺序是「最便宜、最本地的先来」。链上没有任何环节发起网络请求——WARDEN 唯一会发出的下载是
`ThreatFeed.load(url)`，而那是你自己在审查之前调用的。

## 裁定是怎么拼出来的

每个门控返回 `{ findings, score, fatal? }`。整条链：

1. 按顺序运行每个门控，累积发现（每个门控都能看到 `prior`）；
2. 把各门控的评分**相乘**——综合评分是乘积，所以一个坏门控会把整台服务器拉下来，而不是被三个好门控平均掉；
3. 若任一门控返回 `fatal`，或任一非 advisory 的发现达到 `policy.blockAtSeverity`，则阻止；
4. **只有**遇到显式 `fatal` 才短路。会阻止但不 fatal 的发现仍让后续门控继续报告，这样「为什么」的记录才完整。

```ts
const SEVERITY_RANK = { info: 0, low: 1, medium: 2, high: 3, critical: 4 };
```

如果 `policy.blockAtSeverity` 不是这五个键之一，构造函数会写一条警告并回退到 `"high"`。这里的一个拼写错误
曾是最糟糕的故障模式：`rank >= undefined` 在任何比较中都为 `false`，于是一个拼错的阈值会悄无声息地把阻止功能
整个关掉。

### 两个维度：严重级别与层级

严重级别回答的是*这值得多少注意*。**层级**（tier）回答的是*这到底算不算缺陷*——而它是发现上的一项数据
（`advisory: true`），不是严重级别的推论。

带 `advisory` 的发现会被报告，但在**任何** `blockAtSeverity` 下都不会阻止连接、也不会牺牲任何工具。一个 schema
里接受 `api_key` 的工具值得被指出来，但它不是缺陷；用「降低严重级别」来表达这一点，会让它对任何收紧阈值的人重新
变成阻止性的。

## static-scan

对每个工具的 `description` 与 `inputSchema` 做本地正则扫描——只看这两个字段。规则集 **v2** 共 25 条规则：
18 条 `block`，7 条 `advise`。

门控评分为 `1 − 惩罚(最严重的阻止性 severity)`；advisory 命中永远不影响它。

| 最严重的阻止性 severity | 无 | info | low | medium | high | critical |
|---|---|---|---|---|---|---|
| 门控评分 | 1 | 1 | 0.9 | 0.7 | 0.4 | 0 |

| 代码 | 严重级别 | 层级 | 捕捉什么 |
|---|---|---|---|
| `TOOL_DEF_INJECTION` | critical / high | block | 「ignore all previous instructions」「do not tell the user」、`<system>` 标签、对 developer prompt 的引用 |
| `TOOL_DEF_SECRET_REQUEST` | critical | block | `private_key`、`seed_phrase`/`mnemonic`、`~/.ssh` 路径 |
| `TOOL_DEF_SECRET_HARVEST` | critical | block | 自称职责就是读取/导出/披露密钥的工具 |
| `TOOL_DEF_EXFIL` | critical / high | block | 「post to https://…」「forward it to…」「exfiltrate」、上传到某主机的措辞 |
| `TOOL_DEF_HIDDEN_UNICODE` | high | block | 零宽字符与双向控制字符——审阅者看不见的文本 |
| `TOOL_DEF_BASE64_BLOB` | high | block | 描述里长达 120+ 字符的 base64 串 |
| `TOOL_DEF_DATA_URL` | high | block | `data:…;base64,` 与 `javascript:` 形式的 URL |
| `TOOL_DEF_CREDENTIAL_PARAM` | medium / low | advise | schema 或描述索要 `api_key`、`password`、`secret`、bearer 令牌 |
| `TOOL_DEF_ENV_REFERENCE` | medium | advise | `.env`、「environment variables」 |
| `TOOL_DEF_IMPERATIVE` | low / info | advise | 「you must」「instead of」——提示词形态的措辞，单独并不能证明任何事 |

`staticScanRuleset()` 会连同**正则源码与 flags** 一起返回每条规则，好让第三方能重跑一模一样的规则；同时返回
`{ version, digest }`，其中 digest 是对已排序规则列表的 RFC 8785 规范化形式做的 sha256。排序按 code-unit 比较，
绝不用 `localeCompare`：依赖 locale 的排序会让同一张规则表在配置不同的主机上算出不同的摘要，而这正是摘要本身
要检测的分歧。

## threat-feed

把服务器身份和工具定义与 `ThreatRecord` 比对——11 条内置，加上已签名 feed 追加的内容（见
[feed 契约](threat-feed.zh.md)）。

- 任何命中 ⇒ 门控评分 **0**。
- **只有**当 `critical` 记录命中*服务器*时才 `fatal`。命中某个*工具*的 critical 不是 fatal，于是链上其余门控
  仍会报告，责任也仍限定在那个工具上——这正是让一台大体正常的服务器在隔离掉一个工具后继续可用的原因。
- `ThreatRecord.scope` 选择比对面：`server`（id/name/url/command/args）、`tool`
  （name/description/inputSchema），或 `any`——记录省略该字段时的默认值。

内置代码：`THREAT_TYPOSQUAT`、`THREAT_CRYPTO_DRAINER`、`THREAT_SEED_PHRASE`、`THREAT_SSH_KEY_READ`、
`THREAT_ENV_EXFIL`、`THREAT_DESTRUCTIVE_CMD`、`THREAT_FORK_BOMB`。

## origin

这台服务器是运营者声明过的，还是来自远端目录（`McpServerRef.catalog` 有值）？

| `allowUnknownServers` | 发现 | 评分 | fatal |
|---|---|---|---|
| `false`（失败即关闭） | `SERVER_UNDECLARED`，high | 0 | 是 |
| `true` | `SERVER_UNDECLARED`，info | 1 | 否 |

这个开关过去的含义是「还没有信誉评分」，而没有任何部署能满足它：从来没有人给预言机提供过信任边，于是每台服务器
回来都是「无人担保」，`false` 就把它们全都拦住了。而「来自目录」是宿主本地已经掌握的事实，不需要网络，也不可能
死锁。

## pinning

把当前的工具定义与用户批准过的快照做比较。哈希是对定义集合的 RFC 8785 规范化形式做的 sha256——与 feed 签名用的是
同一套规范化，而不是第二种序列化。

| 情形 | 代码 | 严重级别 | 评分 | Fatal |
|---|---|---|---|---|
| 尚无 pin（首次接触） | `TOOL_DEF_UNPINNED` | info | 0.9 | 否 |
| 哈希与 pin 不一致 | `TOOL_DEF_DRIFT` | high | 0 | 当 `pinToolDefs` |
| 工具定义没有规范形式（无 pin） | `TOOL_DEF_UNCANONICAL` | medium | 0.5 | 否 |
| 工具定义没有规范形式（有 pin） | `TOOL_DEF_UNCANONICAL` | high | 0 | 当 `pinToolDefs` |

首次接触的代价是 0.1，而不是阻止：一台干净、已声明、尚无 pin 的服务器恰好得 **0.9**，而 `TOOL_DEF_UNPINNED`
被刻意定为 `info`——在 `blockAtSeverity: "info"` 下，若首次相见就阻止，那么任何服务器都将永远不可用，因为在被
批准过一次之前，什么都无法固定。

`warden.approve(server, tools)` 通过你的 `PinStore` 写入 pin。该操作是幂等的。

## 按工具划分

`allowedTools` / `blockedTools` 把已公布的工具分成两部分：

- 若某条非 advisory 的发现点名了某个工具（`finding.tool`）并达到阈值，则该工具**被阻止**；
- 其余工具全部允许；
- 敏感工具（`policy.sensitiveToolPatterns`）仍然是*被允许的*——它们只是被标记出来，好让你的智能体主循环在运行时
  对每次调用要求审批。参见 `classifyTools` / `isSensitiveTool`。

## 新增一个门控

`WardenGate` 只是三行接口，而 `new Warden({ gates, policy, log })` 直接接受整条链，所以你可以插入自己的门控而
不必 fork：

```ts
import { Warden, StaticScanGate, ThreatGate, OriginGate, PinningGate } from "@aimarket/warden";
import type { WardenGate, WardenGateInput, WardenGateResult } from "@aimarket/warden";

class DenyByPublisher implements WardenGate {
  readonly name = "publisher-allowlist";
  async evaluate(input: WardenGateInput): Promise<WardenGateResult> {
    const ok = ALLOWED.has(input.server.name);
    return ok
      ? { findings: [], score: 1 }
      : { findings: [{ gate: this.name, severity: "high", code: "PUBLISHER_UNKNOWN",
                       message: `${input.server.name} 不在允许的发布者名单中` }],
          score: 0, fatal: true };
  }
}

const warden = new Warden({
  gates: [new StaticScanGate(), new ThreatGate(feed), new DenyByPublisher(), new OriginGate(), new PinningGate(store)],
  policy,
});
```

自己写门控时有两条规矩：**没有真的发出请求，就绝不宣称远端服务不可达**
（`test/no-phantom-gate.test.ts` 会对随包发布的门控强制这一点）；以及返回一个你能站得住脚的评分——什么都没测量的
门控必须返回 `1`，而不是一个「中性」的 0.6，否则它就是在为一次从未做过的测量惩罚每一台服务器。
