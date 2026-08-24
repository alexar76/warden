# WARDEN 在 1 108 个公开 MCP 服务器上发现了什么——以及它判错了什么

> 🌐 [English](mcp-survey.md) · [Русский](mcp-survey.ru.md) · [Español](mcp-survey.es.md) · [Français](mcp-survey.fr.md) · **中文**

2026-08-24，在发布 `@aimarket/warden` 0.3.0 后的几小时内，我们把它指向了所有能够正当访问的公开 MCP
服务器：官方注册表中列出的 2 787 个带网络端点的服务器，其中 1 108 个响应了真实的 `tools/list`，交出了
17 491 条工具定义。

结论的重点不在生态，而在我们自己。WARDEN 拦截了这 1 108 个服务器中的 50 个，而在这 50 个里，我们只能
为 **4** 个找到站得住脚的理由。剩下的 46 个是我们的扫描器判错了——错法有六种，每一种我们都能命名、复现
并修好。

我们连同证据一起公布这些失败，因为一个扫描器的误报画像，是决定别人会不会真的把它打开的唯一数字。一个
拒绝诚实服务器的工具投毒扫描器不是谨慎，而是会被卸载；ruleset v1 已经教过我们一次了。

## 测量了什么

| | |
|---|---|
| 被测包 | `@aimarket/warden@0.3.0`，从 npm 注册表安装到空项目——不是工作副本 |
| 生效的 ruleset | v2，`sha256-gWC14PR4kUylkJaAGMnIYYX6tPhZTJ60cSB61UZxuWc=`（见下文[发布缺陷](#发布缺陷)） |
| 语料 | `registry.modelcontextprotocol.io`，8 000 条记录 → 3 121 个唯一服务器 → 2 787 个带远程端点 |
| 获取方式 | 通过 streamable-http 发送 MCP `initialize` + `tools/list`，每台服务器一次尝试，超时 20 秒 |
| 运行的 gate | `static-scan` 与 `threat-feed`（内置拒绝列表，无远程 feed） |
| 未运行的 gate | `origin` 与 `pinning`——两者判断的是*宿主状态*（运营者是否声明过该服务器、其定义在批准后是否漂移），都不是服务器自身的属性；在普查中它们对全部 1 108 个会返回同一个答案 |
| 策略 | `blockAtSeverity: "high"`、`allowUnknownServers: true`、`pinToolDefs: false` |

**没有执行任何第三方代码。** 每一条工具定义都来自服务器本人通过网络给出的回答。这也是语料为何是远程服务器
而不是各种 awesome 清单里的 stdio 服务器：要碰那些就得下载并运行陌生人的代码，而一份安全普查不该随便这么做。

### 可达性——本身就是一项发现

注册表所宣称的远程端点里，只有 41% 完成了握手：

| 结果 | 服务器数 |
|---|---|
| 响应了 `tools/list` | 1 149（41.2%） |
| 以 4xx 拒绝（需要认证，或已不存在） | 1 215 |
| 连接 / TLS 失败 | 298 |
| `sse` 传输，未尝试 | 37 |
| 5xx | 34 |
| 协议不匹配（没有可用的 `initialize` 结果） | 21 |
| 重定向 / 410 / 429 | 32 |

在响应的 1 149 个中，1 108 个宣称了至少一个工具。任何要对接该注册表的客户端，都应按 **59% 的首次接触失败率**
来设计重试与认证处理。

## 结果

| | 服务器 | 发现数 |
|---|---|---|
| 已扫描 | 1 108 | 3 964 |
| 干净 | 664 | — |
| 有发现但放行 | 394 | 3 472 条 advisory |
| **被拦截** | **50** | **492 条拦截级** |

按规则统计的拦截级发现。一个服务器可能触发多条规则，因此服务器一列加起来不等于 50：

| 代码 | 发现数 | 服务器 | 复核结论 |
|---|---|---|---|
| `TOOL_DEF_SECRET_REQUEST` | 401 | 13 | 4 项成立，9 项属极性盲视 |
| `TOOL_DEF_DATA_URL` | 31 | 11 | 全部误报——`JavaScript:` 与图像 API 示例 |
| `TOOL_DEF_INJECTION` | 21 | 13 | 全部误报——`system prompt` 属领域词汇，以及诚实性指令 |
| `TOOL_DEF_SECRET_HARVEST` | 14 | 10 | 全部误报——动词+名词搭配，30 字符窗口 |
| `THREAT_CRYPTO_DRAINER` | 9 | 4 | 全部误报——子串通配 |
| `TOOL_DEF_HIDDEN_UNICODE` | 5 | 1 | 全部误报——波斯语 ZWNJ |
| `TOOL_DEF_BASE64_BLOB` | 3 | 2 | 全部误报——JSON Schema 的 `$ref` 指针 |
| `THREAT_SEED_PHRASE` | 3 | 2 | 全部误报——子串通配 |
| `TOOL_DEF_EXFIL` | 3 | 3 | 全部误报——安全工具在点名攻击手法 |
| `THREAT_SSH_KEY_READ` | 2 | 1 | 全部误报——文档化的 `ssh -i` 调用 |

按服务器而不是按发现数计：同一行模板文字重复在 377 个工具里，是一个缺陷，不是 377 个。四项成立的案例都落在
两条凭据规则上。

## 站得住的部分

有四个服务器所宣称的工具，确实会让密钥材料经由模型上下文流动。我们描述而不点名：它们并非在作恶，而是在用一种
智能体宿主确实应该加以把关的方式做正当的工作，而普查不是漏洞披露的场合。

- 一个预测市场的资金服务器，其工具接收 `signer_private_key`，描述为 *"signer EOA private key, 0x…"*。
  钱包签名密钥，作为 API 参数索取。这正是 WARDEN 存在的理由。
- 一个智能体间支付服务器，它开出沙盒钱包并通过工具通道
  *"return[s] its private key exactly once"*。
- 一个智能体身份服务器，其工具正文指示模型读取本地 `credentials.json`，并把 `private_key` 以 JWK 形式
  用 `chmod 0600` 写入磁盘。
- 一个托管数据库服务器带有 `pvkPassword` 参数——*"Password that encrypts the private key"*。这是某大型云
  API 的文档化参数，但它仍然是工具 schema 里的一份凭据。

即 50 个被拦截中的 4 个，或 1 108 个被扫描中的 4 个。下面全部是关于另外 46 个的。

## 站不住的部分

### 1. 极性盲视——最大的缺陷

`TOOL_DEF_SECRET_REQUEST` 匹配名词短语 `private key`。它不读周围的句子。于是以下全部以 `critical` 被拦截，
而 `critical` 是致命级——整个服务器、所有工具：

> Never send a private key: none is needed and the request is refused if one is present.
> ——一个 DANE/TLSA 记录生成器

> Use this to import your own public key so you can SSH into instances. **The private key never
> leaves your machine.**
> ——一个云实例管理器

> YOU sign and broadcast the returned transaction yourself, with your own wallet's private key, on
> your own infrastructure — **Otto never sees or holds your key**.
> ——一个兑换报价服务器

> …does NOT confirm the certificate matches any private key.
> ——一个证书检查器

> Use exact field names from this schema; **do not guess aliases or include private key material.**
> ——一个 SAP 服务器，出现在**它全部 377 个工具**的 schema 模板里

最后一例把整个问题的形状压进了一行：一个叫模型*不要*发送私钥的服务器，与索取私钥的服务器得到相同的评分；又因
为该规则是 `critical` 因而致命，共享模板中一次名词命中就把一个 377 工具的服务器打到 0.00 分。我们 492 条拦截级
发现中的 390 条，都出自这一个名词。

`TOOL_DEF_SECRET_HARVEST`——`read|extract|retrieve|fetch|obtain|dump|reveal|collect|…` 中的动词，出现在凭据
名词 30 字符之内——同样如此失效：

> Anyone holding the URL can read it, so **never store secrets**, credentials or personal data
> ——一个临时存储服务器

> Public read-only: **never collect card data, secrets or email**
> ——一个预订咨询服务器

> it does **not** reveal or mint a standalone agent credential
> ——一个智能体注册服务器

三个服务器因为书面承诺不做规则所找的事，而被拦截。

### 2. 角色盲视——扫描器自己被拦

一条*描述*攻击的工具定义，被当作*实施*攻击来评分。五个服务器，全部是防御性工具：

> …for prompt-injection and social-engineering (`'ignore previous instructions'`, `'send funds to'`,
> `'approve this'`, `'admin override'`, `'claim your airdrop'`…)
> ——一个指令检查器，因 `ignore previous` 被拦

> hidden directives that hijack agents — instruction overrides, `'don't tell the user'`, data
> exfiltration, secret harvesting, tool-shadowing, and invisible-unicode / homoglyph steganography
> ——一个 MCP 端点扫描器，因 `exfiltration` 被拦

> `"enum": ["exfiltration", "recon_then_destroy", "injection_then_action"]`
> ——一个策略构建器，因自己的 enum 取值被拦

> Detect likely leaked API keys, tokens, private-key headers, JWTs…
> ——一个密钥扫描器，因 `private-key` 被拦

攻击者写投毒工具时不会点名攻击。防御者每句话都在点名。我们的规则筛出了防御者。

### 3. "do not tell the user" 是一条诚实性指令

`TOOL_DEF_INJECTION` 把 `do not tell the user` 当作隐瞒。而在我们找到的所有真实实例中——四个服务器，四比
零——恰恰相反：服务器是在阻止模型对用户说*假话*。

> some convert in real time during the session, others batch once or twice daily, so **do NOT tell
> the user** a payment is "held until the next session"

> AFTER payment succeeds, no refund is issued automatically — the result says so explicitly; **do
> not tell the user** a refund is coming

> a `facturx-en16931` result is the payload and not a Factur-X document — **do not tell the user
> otherwise**

> **Do not tell the user** to drag assets into chat

在真实数据上，这条规则的前提是反的。认真的服务器作者用这句话来压制凭空编造的安慰之词——而这恰恰是智能体宿主
想要的行为。

### 4. 词汇撞车

- **`system prompt`** → `TOOL_DEF_INJECTION`，6 个服务器上 15 条发现。全部是 LLM 代理、人格管理器或智能体
  配置工具，其全部目的就是设置 system prompt，并在 schema 中声明 `system` 参数。这个词在这里是领域，不是攻击。
- **`\bjavascript:`** 带 `i` 标志 → `TOOL_DEF_DATA_URL`，high。它会匹配 *JavaScript* 一词后跟冒号，而世上
  任何语言清单都是这么写的：*"TypeScript/JavaScript: `*.spec/test.{ts,js}`"*、*"plain async JavaScript: …"*、
  *"javascript: Enable JavaScript execution"*。它同样会在声明自己**剥离**该 scheme 的服务器上触发：
  *"the sanitizer strips … `javascript:` and `data:text/html` URIs"*。
- **`data:…;base64,`** → 同一条规则，命中 schema 示例字面写着 `"<url> OR data:image/png;base64,..."` 的图像
  API，也命中了一个声明**过滤** `data:` scheme 的抓取器。
- **`SECRET_HARVEST` 的 30 字符窗口**会跨过句子与 JSON 边界：`read an open or sealed run (pass api_key`
  就是一处从正文跨进参数名的命中。

### 5. 编码盲视——WARDEN 标记了一种文字

`TOOL_DEF_HIDDEN_UNICODE` 报告 "zero-width or bidi control characters hiding text from review"。一个服务器
触发了五次。那是一个伊朗的法律计算服务器，而该字符是 **U+200C ZERO WIDTH NON-JOINER**——波斯语中*必需*的
正字法字符：

- `بخشنامه‌ها`（通告）
- `سهم‌الارث`（继承份额）
- `حق‌الثبت`（登记费）
- `حق‌التحریر`（公证费）

没有任何东西被隐藏。这门语言就是这么拼写的。照现在的写法，这条规则因正字法而惩罚波斯语、阿拉伯语和印度系文字的
服务器——一项读起来像语言政策的安全控制，这比误报更糟。

`TOOL_DEF_BASE64_BLOB` 有镜像式的毛病：`/` 属于 base64 字母表，于是一个深度嵌套的 JSON Schema 指针——
`#/properties/flow/items/anyOf/2/properties/outcomes/items`——被报成 "a long base64-encoded blob —
possible hidden payload"。

### 6. threat-feed 的通配符会命中子串

内置拒绝列表用 `*a*b*` 形式的通配符去匹配拼接后的工具定义，既无词边界也无邻近约束：

- `*sweep*funds*` 命中了一个 ENS 扫地板工具：*"Floor-sweep: buy the CHEAPEST N listed ENS names"* …
  *"and **refunds** the excess"*。该模式在 **refunds** 一词内部找到了 `funds`。
- `*drain*wallet*` 命中了一个反 drainer 扫描器：*"Find risky allowances that could **drain** your tokens"* …
  *"a **wallet** granted"*。这个工具的存在就是为了阻止 drainer。
- `*seed*phrase*` 命中了一个 YouTube 关键词工具：*"For a **seed** topic, returns suggested search
  **phrases**"*。

三者都以 `critical` 报出，消息为 *"Crypto-drainer keyword in server identity"*——而这句话连命中*位置*都说错了：
它们命中的是工具定义，不是服务器身份。

## 完全按设计工作的部分

整套 ruleset 中唯一毫发无损通过实战的，是**分级**。`advisory` 级发现触发了 3 472 次——
`TOOL_DEF_CREDENTIAL_PARAM` 2 016 次、`TOOL_DEF_IMPERATIVE` 1 437 次、`TOOL_DEF_ENV_REFERENCE` 19 次——
没有拦截任何东西，没有扣任何分，也没有隔离任何工具。在 ruleset v1 下，schema 里的 `api_key` 是拦截级的，这
2 016 次命中会拒掉相当大一部分诚实生态。v1→v2 的教训在真实数据上成立；剩下的活都在拦截级规则里。

## 发布缺陷

我们用来扫描的包报告 ruleset **v2**，digest `sha256-gWC14PR4…`。**同一个 tarball 内**的 README 记载的是
ruleset **v3**，并打印 digest `sha256-pah/sT4I…`。两句话都对——只是说的是不同的代码：

| | |
|---|---|
| `0.3.0` 发布到 npm | 2026-08-24 08:34:08 UTC |
| 抽出该包的提交 | 2026-08-24 08:35:12 UTC——64 秒之后 |
| 引入 ruleset v3 的提交 | 2026-08-24 09:26:50 UTC——发布之后 52 分钟 |

也就是说，陌生人安装到的产物在 `name` 这个面上没有任何规则，而 v3 的 24 条规则中有 17 条覆盖该面；工具*名字*里
的零宽字符或 base64 块，对它是不可见的。

然后我们测了这代价有多大。我们用 v3 构建在同一份语料上重跑，并按服务器、按工具、按代码逐项比对：

**零差异。** 444 个有发现的服务器、50 个被拦截、3 964 条发现——两套 ruleset 完全一致。1 108 个真实服务器中，
没有任何一个在工具名里放了 v3 能抓到而 v2 会漏掉的东西。过期发布是一个真实的流程缺陷——对应的 CI 校验是下文第 9 项；但在这份语料上
它对行为的影响为零，我们宁愿把这点说清楚，也不愿暗示一个我们并未测到的严重性。

## 因此要改什么

按每一项能修掉 46 个中的多少来排序：

1. **极性。** 同一小句中被否定标记（`never`、`not`、`no`、`does not`、`without`、`refused`）领起的凭据名词
   不是索取。在此实现之前，仅凭名词的命中不得为 `critical`，因为 `critical` 是致命级，而共享模板里的一个名词
   绝不该拖垮 377 个工具。
2. **引号内与枚举中的文本。** 出现在字符串字面量、JSON `enum` 或逗号分隔的分类法里的短语是*提及*。提及不拦截。
3. **`do not tell the user`** → 降为 `advisory`，等到有一条要求隐瞒对象（该工具、该转账、该文件）而非仅凭这句话
   的规则再说。
4. **`\bjavascript:`** → 改为区分大小写并要求 URI 上下文；作为标签的 `JavaScript:` 不是 scheme。
5. **U+200C / U+200D** → 与阿拉伯、波斯或印度系文字相邻时豁免。U+200B、U+FEFF 和 bidi 覆写继续标记。
6. **base64 检测** → 排除 JSON 指针与路径；要求补位或熵阈值，而不只是字母表。
7. **threat-feed 通配符** → 采用词边界语义与邻近上限，使 `*sweep*funds*` 无法命中 `refunds`。
8. **发现消息** → 携带经净化的命中片段。我们现在把模式截断成 `signature (\b(?:read|extract|…)`，复核者不看源码
   就无法知道是哪个分支触发的。在这份普查里，这一点就花掉了我们几小时。
9. **CI 中校验 ruleset digest** → 若已发布的 `dist` 报告的 ruleset 版本与构建它的源码不一致，发布必须失败。

## 局限

- **只有一种传输。** 仅 streamable-http；37 个 `sse` 服务器被跳过，而生态中所有 stdio 服务器都因"不执行代码"
  的原则被排除在外。而 stdio 服务器恰恰是人们真正在本地运行的大多数。
- **只有一个时点。** 2026-08-24 每台服务器一次 `tools/list`。工具定义会变，抓取时诚实的服务器之后可以换掉描述
  ——这正是 `pinning` gate 的用处，而 pinning 恰恰是这次普查无法演练的。
- **"误报"是我们的判断。** 我们读了工具定义，判定这个标记是错的。我们没有审计这些服务器，而*定义*上的误报并不
  为*实现*作保：正文无可指摘的工具，在被调用时仍可能外泄数据。对工具定义做静态扫描，从构造上就看不见这件事。
- **没有基准标注。** 这份语料没有任何标签。我们能报告 50 次拦截里有 46 次是错的；我们无法报告有多少投毒服务器
  被我们径直走过。假阴性对这套方法是不可见的，而 4/50 的精确率对召回一无所言。
- **需认证的服务器缺席。** 1 215 个服务器在无凭据时拒绝了。这些不成比例地是商业服务器，因此语料偏向开放和业余
  的一侧。

## 自行复现

这里的一切都不需要我们的基础设施，也不需要任何密钥。脚本在
[`scripts/mcp-survey/`](../scripts/mcp-survey/)，汇总在
[`data/mcp-survey-2026-08-24.json`](data/mcp-survey-2026-08-24.json)。

```bash
cd scripts/mcp-survey
python3 harvest_registry.py          # 注册表 -> registry_remotes.json
python3 harvest_tools.py             # 实时 tools/list -> tools_raw.jsonl
npm install @aimarket/warden@0.3.0
node scan.mjs tools_raw.jsonl scan.json
python3 classify.py                  # 每条拦截级发现的精确命中片段
```

`harvest_tools.py` 每台服务器发两到三个请求，不执行任何东西。若你重跑，可达性数字会与我们的不同——端点按小时
出现和消失。

## 基线

留个记录，好让下一次读这些数字时有意义。2026-08-24，既是本次普查当天，也是 0.3.0 发布当天：

| | |
|---|---|
| npm 版本 | 0.3.0，08:34 UTC 发布 |
| 0.3.0 的 npm 下载量 | 无记录——注册表计数只到 2026-08-23，因此尚无它的数据 |
| 前一周 npm 下载量 | 1 次，来自 `0.0.1` 占位版本 |
| GitHub 星数 | 0 |

无论这一页下次更新时这些数字变成什么，它们就是从这里开始的。
