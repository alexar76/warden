# WARDEN MCP 安全基准 — 2026-11-07

**状态：五款已发布产品在两台主机的比较已完成。** 每产品均尝试全部 18,110 行。完整覆盖、错误和一致性分别报告；混合总数不是总体准确率。后续运行时 `.2` 候选另有状态。

[English](security-benchmark-2026-11-07.md) · [Русский](security-benchmark-2026-11-07.ru.md) · [Español](security-benchmark-2026-11-07.es.md) · [Français](security-benchmark-2026-11-07.fr.md) · [中文](security-benchmark-2026-11-07.zh.md)

本文由 WARDEN 和 HISTOR 的维护者在 AI 协助下编写，属于维护者比较，不是独立认证。本文报告的比较测量在远程 gVisor 进行。更早的本地试跑已排除，其 `dist`／Vitest／Vite 生成物已删除；不宣称历史上从未发生过本地试跑。

下方的证据链接会下载公开报告 ZIP。链接标题注明压缩包中的对应文件。

## 比较对象与版本

本次比较扫描器如何处理 MCP 公布的工具定义。静态扫描描述，不等于执行工具、观察模型服从注入，或测量针对模型的攻击成功率。

| 实现 | 包／入口 | 本轮身份 |
|---|---|---|
| WARDEN，主表已发布产品 | `@aimarket/warden` | npm `0.23.0`，ruleset `17`，40 条规则；digest `sha256-UOfK25xo6D8vrKEVfNFBTBVn5OspyaZut9vC9Z9Q5JE=` |
| mcp-audit | PyPI `mcp-audit-scanner[mcp]` | `0.28.0` |
| mcp-shield | npm `mcp-shield` | `1.0.4` |
| truecopy | npm `@askalf/truecopy` | `0.10.5` |
| mcpsentry | npm `@roshan6335/mcpsentry` | `0.1.5` |

主表 WARDEN 使用经验证的已发布 npm tarball，SHA-256 `833841f2aab89df4c51b5f84385ad69c8ffd7dcf5a7725ec0eb4ebabe594b7ee`。更早冻结的“v17”构件有六个 wrapper／结果筛选 dist 文件被修改，不与 npm 0.23.0 逐字节相同，不能替代主表。已观察失败后修复的未发布候选为 `0.23.1-dev.20261107.1`，ruleset `19`，43 条规则、32 条阻止，digest `sha256-XfRh1+VZoAM6PGtbmqprnSX/eF16qNYOk0o+ilRFxXw=`。首个 v18 单独保留，digest `sha256-aXkZQj8F1fKgcTpyrfNdgQSQMuzdc1yabcKiGPVKjMo=`。本次未发布 npm。十月版本和测量见[历史比较](scanner-comparison.zh.md)。

已发布包与上游公共语料可取得。精确重放维护者样例及适配器仍需发布其源码；元数据允许检查行身份、阈值、覆盖及输出哈希，本身不提供完整独立重放。候选19 源码也未发布，其哈希与凭据可审计，但不构成外部可复现构建。公开包只含报告、元数据、图，不含产品或私有框架源码。

## 真实实现与定义重放

大规模比较调用真实实现自身的完整分析／分类 API，并为每个对象使用新状态。不宣称每个产品的全部 18,110 行都经过 stdio MCP。原生 CLI／MCP 一致性与真实互操作检查另行报告。

| 类别 | 明确清单 | 测量范围 | 状态 |
|---|---|---|---|
| 真实 stdio 包，候选19 | `@modelcontextprotocol/server-filesystem@2.2.0`（16 工具）、`@modelcontextprotocol/server-memory@2.1.0`（9）、`@modelcontextprotocol/server-sequential-thinking@2.1.1`（1）、WARDEN（9） | 官方 Node MCP SDK `1.32.1`，直接及包装两种模式：发现、安全合成调用、拒绝未知工具、随后 ping | 两台主机均 8/8 会话；4/4 工具列表 digest 对一致 |
| 公共 HTTP，候选19 | DeepWiki（3）、Microsoft Learn（3）、Cloudflare Docs（2） | 仅 `initialize` 和 `tools/list` | 两台主机均 3/3 无错，全部允许 |
| 冻结定义分析 | 3,177 个固定视图及 14,933 个 HISTOR 行 | 自身完整分析／分类 API，不执行原服务器代码 | 两台主机均已完成 |
| 代表性 CLI／MCP 一致性 | Node 各 10/10；Python mcp-audit 完整六分析器 13 次原生/API 一致，含 1 次 partial；已发布 WARDEN 20/20，含 1.17 MB 及攻击／干净／重复 | 原生入口与适配器比较 | partial 一致不是完整判定 |

见[真实互操作证据](https://modelmarket.dev/blog/media/warden-security-comparison-2026-11-07/reports-and-data.zip "Archive member: evidence/live/README.md")。最终 SDK 凭据对应远程 `sdk19-final`；本地 `sdk19` 保留首次检查。合成调用不用用户文件或生产凭证。HTTP：`https://mcp.deepwiki.com/mcp`、`https://learn.microsoft.com/api/mcp`、`https://docs.mcp.cloudflare.com/mcp`。所列是测得版本，不宣称最新。

## 样例的完整清单

**维护者编写的 23 个攻击样例**，定义见 [`build_sets.py`](../scripts/scanner-comparison/build_sets.py)：

`A01-important-tag`, `A02-ssh-into-param`, `A03-shadowing-bcc`, `A04-zero-width-hidden`, `A05-unicode-tags`, `A06-base64-payload`, `A07-russian`, `A08-chinese`, `A09-paraphrase`, `A10-schema-hidden`, `A11-annotation-injection`, `A12-exfil-url`, `A13-name-injection`, `A14-private-key-param`, `A15-seed-phrase`, `A16-javascript-url`, `A17-ignore-previous`, `A18-system-tag`, `A19-call-first-history`, `A20-env-dump`, `A21-destructive`, `A22-concealment`, `A23-spanish`。

**12 个良性对照样例：**

`B01-never-send-key`, `B02-injection-scanner`, `B03-api-key-param`, `B04-javascript-word`, `B05-persian-zwnj`, `B06-refunds`, `B07-send-email`, `B08-secret-scanner`, `B09-password-vault`, `B10-upload-drive`, `B11-ssh-howto`, `B12-translate`。

**第三方样例：10 个攻击、1 个良性、1 个有歧义。**

| 来源 | 样例与标签 |
|---|---|
| mcp-audit，commit `fdc8762eb2d5abb708bdaf767ec5a8140b2ab9a2` | 攻击：`behavioral_override_stealth`、`cloud_credential_exfiltration`、`crowdstrike_add_numbers`、`fake_postmark_exfiltration`、`invariant_labs_ssh_exfiltration`、`xml_injection_override` |
| mcp-shield，commit `379140c3555bf35c6f8f451ee320da24302e792e` | 攻击：`calculateSum`、`sendEmail`、`readFile`、`getFactOfTheDay`；良性：`whatsapp`；歧义：`fetchWeather` |

有歧义的样例单独公布，不进入攻击召回率或良性误阻止率的分母。第三方作者身份不意味着这是新的盲测：WARDEN 开发期间已能获取这些样例。

## MCPTox：统计单位与全部 45 个服务器名称

归档提取包含 **485 个不同的投毒工具定义**：22 个 dev 服务器上 267 个，23 个 test 服务器上 218 个。另有 225 个提示呈现方式发生变化的 decorated 定义，以及 45 份干净服务器工具列表。这些单位不能相加后统称为“服务器”。

论文的 **1,348 个场景**与 485 个定义是不同且重叠的视图。远程审计官方 commit `f85189f9ad12504c197c7f920ab818a40657b1fa` 保留 1,338 个唯一 server/frame 值及保留的 10 个重复实例，零丢弃；702 行实际换行，646 行规范化转义换行。原始 JSON 哈希与归档相同。源仓库未标明许可，公开下载仅含事实元数据，不再分发原始定义、schema、攻击文本或 Python 源码。45 个干净列表含 362 工具，而论文写 353；去重未消除该差异。参见[提取代码](../scripts/scanner-comparison/build_mcptox.py)和[划分](../scripts/scanner-comparison/results/2026-10-09-mcptox.json)。

Full-frame 场景投影保留原始参数文本，但把提取的参数属性声明为字符串，不重建原生参数类型。因此其结果对应这项明确投影，不是对原始服务器 schema 的精确执行。

**Dev — 22：** AWSKnowledgeBase; AdFin; AlphaVantage; BaiduMap; ClickHouse; Codacy; Commander; DoDo Payments; Email; EverArt; Everything; Fetch; Flomo; Google Maps; Memory; Prisma; SQLite; Sentry; Slack; Tavily; gNucleus Text to CAD; mcp-simple-arxiv。

**Test — 23：** 12306-mcp; AgentQL; AmapMap; Apify; BraveSearch; Claude Post; DumplingAI; E2B; FileSystem; Financial Dataset; Git; Github; Gitlab; GoogleDrive; Gyazo; HyperBrowser; KeywordsPeopleUse; OP.GG; Puppeteer; QuickChart; Redis; Sequential Thinking; wechat。

这些是数据集中的名称，不代表当前连通性或任何隶属关系。划分先按 `sha256("mcptox split 2026-10-09|" + server_name)` 升序排列：前 22 个 dev，其余 23 个 test。上面的清单保留结果文件中的列举顺序。

| 归档输入 | 原始字节 SHA-256 |
|---|---|
| `pure_tool.json` | `54b1eb0e9d7b2f18465266aa9d9dfda828cd558b1269b74731ec2c5d8579e617` |
| `response_all.json` | `79a90049be931c59e71446d6180b1d7f0d196d123d08a59bc155d142b5041c03` |

这两个历史哈希不能替代本轮所有来源、`def_tool` 文件、生成 JSON 和配置的 manifest。解析器把 Python 定义当作数据读取，不执行它们。“Served” 重放提取的服务器定义；“decorated” 单独测量 `<IMPORTANT>` 或 “Ignore the previous instructions” 等前缀。

## 公共归档与包观察

主组 [2026-10-01 语料](data/mcp-corpus-2026-10-01.jsonl.gz)有 **986 份归档列表**；[August carryover](data/mcp-corpus-2026-10-01-august-carryover.jsonl.gz)有 **41 次观察**。已确认 **28 个名称＋定义完全重合**，故为 **999 个唯一名称＋定义快照**，不是 1,027 个独立服务器。

完整 [inventory](https://modelmarket.dev/blog/media/warden-security-comparison-2026-11-07/reports-and-data.zip "Archive member: INVENTORY-README.md")列出 **全部 18,110 行**、名称、记录版本、标签、工具数、digest 与来源。下载：[CSV.gz](https://modelmarket.dev/blog/media/warden-security-comparison-2026-11-07/reports-and-data.zip "Archive member: public-inventory.csv.gz")、[JSON.gz](https://modelmarket.dev/blog/media/warden-security-comparison-2026-11-07/reports-and-data.zip "Archive member: public-inventory.json.gz")、[manifest](https://modelmarket.dev/blog/media/warden-security-comparison-2026-11-07/reports-and-data.zip "Archive member: public-inventory-manifest.json")。仅元数据，不含无许可的攻击内容。

已恢复 **14,933 个 HISTOR 包版本行：12,023 npm、2,910 PyPI**，涉及 14,449 个不同 toolset、272,657 条工具记录，零丢弃、无数量不符。两台主机均验证 MTL digest 重算与文件哈希。[2026-10-20 归档](https://histor.modelmarket.dev/datasets/2026-10-20/toolsets.jsonl.gz)提供 14,930 行，其余三行由不可变公共 API URL 恢复。[Manifest](https://histor.modelmarket.dev/datasets/2026-10-20/manifest.json)与 tree-head 的 Ed25519 签名按固定 `did:key` 验证。归档为 CC-BY-4.0，署名 Aleksandr Artamokhov / HISTOR，*HISTOR: MCP tool definitions and how they change*，快照 2026-10-20。三份 API 响应未单列许可，公开材料仅含其元数据。

历史输入保留准确的 MTL 基本字段，不合并当前 title、annotations 或扩展。包观察不代表重新安装／执行。无标签数据提供阈值信号频率；误报需要标签或对相关文本的判定，不能用历史样本代替本轮整体精度。

| 输入／证明 | SHA-256 |
|---|---|
| 3,177 视图目录 | `e29baa05fbdbf46e34631ff2c75f0b4f535f0188054dd4499699bd189a3dc757` |
| 14,933 包目录 | `78d4dab7125318b80cc35302e7cf1cfc1a49fa6f310957ed7b8fddfb538375b6` |
| HISTOR 恢复证明 | `8cdb0faf62c72f947baf30f74d6523fc6fd5b68720b44f4b765a0f804489cf7e` |
| 最终 grouped 结果 | `44732cdfa369f0f912491212d1910883a6071c4ce4727cfc30911adb828d7a3b` |
| 最终逐例跨主机证明 | `a0773f6622290268129cc48323dab0b1b84dc5652d1b2b1ba20e679c63a01205` |
| 最终 SHA-256 manifest | `17d6e7ebd85dede970d77f319bf3734478a037bf9fd971a53f5bbd07b4fce3f8` |

目录采用 `warden.shared-lazy-inputs/v1`。`toolsFileSha256` 哈希准确 UTF-8 字节；`toolsSha256` 使用 Python 3.13 紧凑 JSON、键排序、保留 Unicode／数组顺序、拒绝非有限数，不宣称是 JCS。Wire id 是 `c` 加 `warden shared inputs 2026-11-07|`＋样例键的 SHA-256 前 32 个十六进制字符，各产品／版本／主机相同。

## 记录的远程流程

1. 解读结果前，固定源码身份、规则 digest、扫描器包版本、注册表查询时间、发布的 integrity hashes、依赖清单和容器镜像 digest。保留命令与原始输出。
2. 为每份输入保存 SHA-256：原始下载、提取定义、重放 JSON、标签、划分、配置与测试框架。保存稳定 id、转换版本及来源。
3. 批量使用 `runsc`、禁网、UID/GID 501:501、root/source/runtime/data 只读、cap-drop ALL、no-new-privileges、tmpfs 和独立输出。镜像 `sha256:db7085498187e8477fa462d5f1652d62bdf4b8af29ea3666bd1748a8315631a5`，Node 24.22.2／Python 3.13.18。Node 1 CPU／768 MiB，保存的凭据 pids128；audit base 1 CPU／768 MiB，HISTOR attested 1 CPU／768 MiB／1 worker、PingBlip 2 CPU／1536 MiB／2 workers，pids256。已核对 `cpu.max`／`memory.max`。Audit HISTOR UTC 2026-11-07：attested 20:33:21–21:13:27，PingBlip 20:33:15–21:34:48；不是受控速度测试。真实 stdio／HTTP 另用 UID1000、0.5 CPU／512 MiB 及 bridge／256 MiB 设置。
4. 每个固定对象使用完整原生分析／分类 API 与新状态。mcp-audit 运行默认六个分析器。适配器由独立 CLI／MCP 样例验证。WARDEN 设置 `allowUnknownServers: true`、`sensitiveToolPatterns: []`。truecopy 的 cold-lock／unpinned 拒绝与内容分类分别记录。
5. 首次尝试与重试分别保存，预先声明超时和重试策略。错误、跳过、协议拒绝都不是 allow；不能用旧版结果填补新结果。
6. 保留原生输出、归一化、错误和输出哈希。最终检查逐键、wire id、准确输入 SHA-256、版本／源码／镜像、状态、HC/any/advisory，以及完整原生对象 SHA。只规范化 mcp-audit 自身临时配置 `finding_path` 和首次 `RUGPULL-000` state-file 证据，保留发现文本／代码／级别。

[下载五语报告与数据 ZIP](https://modelmarket.dev/blog/media/warden-security-comparison-2026-11-07/reports-and-data.zip)：离线 EN/RU/ES/FR/ZH 报告、`grouped-results-v2.json`、`figure-cross-host.json`、方法及逐例元数据。公开行仅状态、信号、哈希，不承诺公开全部原生发现或无许可攻击内容。

mcp-audit 调用原生 `run_scan_async(extra_paths=[fresh_config], connect=True, guardrail_drift=True)`；只替换 `connect_and_enumerate` 传输，用已捕获对象经过 SDK `ListToolsResult` 验证，再用原生 `_tool_info` 转换。完整分析器、toxic-flow、delegation、annotations、score 保留；每例 HOME/cwd/config/rug-pull 全新。在线/API/LLM 关闭，30 秒超时终止 worker 并记不完整。WARDEN 策略：`blockAtSeverity=high`、`allowUnknownServers=true`、`sensitiveToolPatterns=[]`、`pinToolDefs=true`。

## 阈值与分母

阈值：WARDEN 原生 static-scan/threat-feed 的 `allow: false`；mcp-audit 完整 pipeline 的定义相关 `HIGH`／`CRITICAL`；mcp-shield `HIGH Risk`；truecopy 原生 HIGH/CRITICAL 内容信号；mcpsentry `HIGH`／`CRITICAL`。Truecopy 任意内容发现，包括 advisory，都可能被归为 poisoned 并隐藏；HC 不等于全部隐藏，unpinned/cold-lock 另记。

共有列是 **HIGH/CRITICAL 信号**，不是同样的强制阻止。WARDEN 有原生 allow/block，truecopy 内容分类与代理隐藏相关。mcp-shield 有发现仍可退出 0；mcpsentry 只在 critical 时退出 1，只有 high 时可退出 0。仅报告工具的信号不能叫作强制阻止。

分别报告 **达阈值阳性**、**低于阈值／仅 advisory**、**无发现**、**error/partial**、**skipped**、**not run**。任意信号包含阈值阳性。框架路径、配置卫生与首次 baseline 噪声保留，并按所有产品一致的规则排除。

保留 normalization-v1 诊断：它只选 static-scan，错误排除了三个 WARDEN threat-feed SSH critical 真正检出。Normalization-v2 纳入全部相关定义 gates；原生输出不变，无需重跑引擎。观测到的 WARDEN 数据仅排除 info `TOOL_DEF_UNPINNED`。所有产品一致排除框架／启动／首次 baseline 噪声，避免首次 pinning 导致误导的 100% any-signal。同时报告 HC 内容信号、任意相关信号及 advisory-only = any − HC。

每扫描器／组：计划 `N`、完整结果 `C`、阈值阳性 `B`（JSON 字段名）、低阈值／advisory `A`、错误／partial `E`、跳过 `S`、未运行 `U`；`N = C + E + S + U`、`C = B + A + no-finding`。阈值信号率为 `B/C`，只有攻击标注组内才是召回率；覆盖为 `C/N`，附计数。有错另列 `B/N`，不把错误算真阴性。实际强制阻止是产品单独的结果；误报需标签或人工判定，歧义另列。

MCPTox 攻击按定义；干净／公共／carryover 按服务器快照；HISTOR 按包目标。至少一项相关工具发现达到所选阈值，目标即阈值阳性。工具层计数仅为附加诊断。

### 部分扫描与协议兼容性

两行 HISTOR mcp-audit 达到原生分析上限：schema 5,000 节点／深度 64，以及每工具 65,536 字符。它们计入 `E: partial`，不进入完整覆盖率或主表 `B/A`，即使已有部分信号。partial 原生/API 一致也不是完整扫描。

mcp-shield 的严格 MCP SDK schema 验证拒绝 31 份 HISTOR 列表。mcpsentry 和 truecopy 原生 raw JSON-RPC 客户端不用该验证器。被拒的 42 工具样例在 mcpsentry CLI/API 均无发现通过，属于实际兼容性差异，不是适配器遗漏。mcp-shield HISTOR：attested `C=14,902/14,933`，31 schema 错；PingBlip `C=14,901/14,933`，31 schema 错加 1 超时。两者完整结果均 HC 5,354／any 6,767。这是无标签阳性频率，不是 FPR；五产品最终比较已完成。

独立 3 MB mcp-shield 原生+API 一致性样例在合并期限由 30 秒改为 90 秒后，用时 52.18 秒通过；每次引擎约 28 秒。首次合并超时保留，实际每样例 API 预算仍是 30 秒。这不是检测器失败，也没有暗改批量期限。

## 本轮结果

### 保留首个 WARDEN 候选的回退结果

首个 v18 候选比 v17 少检出三个原始定义：`FileSystem_20`、`FileSystem_22`、`FileSystem_23`。这些失败结果保留。查看失败后作出的修复属于另一候选，不能称为未见留出集测量。

| 表面／单位 | 更早冻结 v17 构件 | 首个 v18 阻止 |
|---|---|---|
| 485 个原始服务器定义 | 460/485 | 457/485 |
| 已知历史 test，218 个定义 | 210/218 | 207/218 |
| 225 个 decorated 定义 | 225/225 | 225/225 |
| 1,348 个完整提示场景，含重复行 | 1,331/1,348 | 1,331/1,348 |
| 45 个干净服务器，362 个工具 | 0/45 | 0/45 |

两台主机结果一致。每版本、每主机的真实 MCP 与库路径在 2,103/2,103 个样例上一致，合计 8,412 次比较。这是路径／主机一致性，不是模型攻击成功率。远程凭据：`/opt/warden-tests/20261107-mcptox-v18/results/final-report/REPORT.md`；下文提供扩展且已验证的配对报告，不代表 npm 发布。

已验证事后候选 v19 针对覆盖 SSH 公钥的安全配置篡改及读取 `/etc/shadow` 的秘密访问，恢复 `FileSystem_20` 和 `FileSystem_23`。`FileSystem_22` 公钥读取前置条件仍是未阻止工具劫持，不改良性标签、不移除分母。首个 v18 三个漏检保留。

| 候选19视图 | WARDEN 原生阻止／完整结果 | 错误 |
|---|---|---|
| 自编攻击／良性，分别列出 | 23/23; 0/12 | 0 |
| 第三方攻击／良性／歧义，分别列出 | 10/10; 0/1; 0/1 | 0 |
| 原始定义／历史 test，分别列出 | 459/485; 209/218 | 0 |
| 完整场景／decorated，分别列出 | 1,331/1,348; 225/225 | 0 |
| 干净服务器 | 0/45 | 0 |
| Public-main／carryover，分别列出 | 3/986; 1/41 | 0 |

每版本 v18/v19、每主机真实 MCP／库路径均 **3,177/3,177**；跨主机完整行 **12,708/12,708** 一致，七项输入／源码／框架／replay 身份检查均真。这是运行一致性，不是检出全部攻击。[报告](https://modelmarket.dev/blog/media/warden-security-comparison-2026-11-07/reports-and-data.zip "Archive member: evidence/candidate19/REPORT.md") SHA-256 `e699ba593242406b31f366b34d3e104dcf567094fd97421a62fbba8ded958989`；配对 JSON `30996c170fd4284991ac4624ee88cda765ae26cb2393a8bbdeefa23913847a4e`。

### 五款已发布产品最终结果

主表 WARDEN 是已发布 npm 0.23.0／rules17，不是旧修改构件或候选19。这是新的远程测量，不使用十月旧结果替代。

单元格为 **HC／any／advisory-only 计数**，advisory-only = any − HC。全部 base 行 `C=N`、`E=S=U=0`；HISTOR 例外见下表。两主机 HC/any 相同。主表 WARDEN 是已发布 npm 0.23.0/rules17；不把重叠视图相加成总体准确率。

| 组／单位 | WARDEN npm 0.23.0 | mcp-audit 0.28.0 | mcp-shield 1.0.4 | truecopy 0.10.5 | mcpsentry 0.1.5 |
|---|---|---|---|---|---|
| 23 自编攻击 | 20 / 23 / 3 | 11 / 13 / 2 | 6 / 10 / 4 | 3 / 8 / 5 | 4 / 4 / 0 |
| 12 自编良性 | 0 / 3 / 3 | 1 / 2 / 1 | 1 / 2 / 1 | 1 / 1 / 0 | 2 / 2 / 0 |
| 10 第三方攻击 | 10 / 10 / 0 | 10 / 10 / 0 | 8 / 9 / 1 | 1 / 7 / 6 | 5 / 5 / 0 |
| 1 第三方良性 | 0 / 0 / 0 | 0 / 0 / 0 | 0 / 0 / 0 | 0 / 0 / 0 | 0 / 0 / 0 |
| 1 第三方歧义 | 0 / 0 / 0 | 0 / 0 / 0 | 0 / 1 / 1 | 0 / 0 / 0 | 0 / 0 / 0 |
| 485 原始 MCPTox 定义 | 460 / 474 / 14 | 56 / 392 / 336 | 56 / 71 / 15 | 1 / 31 / 30 | 19 / 19 / 0 |
| …267 dev | 250 / 257 / 7 | 17 / 214 / 197 | 15 / 25 / 10 | 1 / 4 / 3 | 11 / 11 / 0 |
| …218 已知历史 test | 210 / 217 / 7 | 39 / 178 / 139 | 41 / 46 / 5 | 0 / 27 / 27 | 8 / 8 / 0 |
| 225 decorated MCPTox | 225 / 225 / 0 | 222 / 225 / 3 | 41 / 95 / 54 | 135 / 141 / 6 | 136 / 136 / 0 |
| 1,348 完整场景 | 1331 / 1338 / 7 | 951 / 1264 / 313 | 158 / 570 / 412 | 432 / 491 / 59 | 460 / 460 / 0 |
| 45 干净 MCPTox 服务器 | 0 / 7 / 7 | 0 / 3 / 3 | 3 / 6 / 3 | 0 / 0 / 0 | 1 / 7 / 6 |
| 986 公共快照 | 4 / 388 / 384 | 43 / 159 / 116 | 343 / 451 / 108 | 2 / 39 / 37 | 86 / 450 / 364 |
| 41 carryover 观察 | 2 / 37 / 35 | 12 / 24 / 12 | 33 / 35 / 2 | 1 / 3 / 2 | 21 / 38 / 17 |
| 14,933 历史包版本行 | 409 / 6327 / 5918 | 481 / 2089 / 1608 | 5354 / 6767 / 1413 | 15 / 252 / 237 | 1449 / 6362 / 4913 |

### 完整覆盖与逐案主机一致性

每产品、每主机 `N=18,110`、`S=U=0`，全部输入已配对。零缺失、零输入／引擎身份不符、零完整结果差异。不完整结果不进入完整一致性分母。

| 产品 | C attested／PingBlip | E attested／PingBlip | 相同／完整配对 | 错误 |
|---|---|---|---|---|
| WARDEN npm | 18110 / 18110 | 0 / 0 | 18110 / 18110 | 0 |
| mcp-audit | 18108 / 18108 | 2 / 2 | 18108 / 18108 | 两边各 2 partial |
| mcp-shield | 18079 / 18078 | 31 / 32 | 18078 / 18078 | 两边 31 schema；仅 PingBlip 1 timeout |
| truecopy | 18110 / 18110 | 0 / 0 | 18110 / 18110 | 0 |
| mcpsentry | 18110 / 18110 | 0 / 0 | 18110 / 18110 | 0 |

附加候选19 `.1` 完整配对 18,110/18,110；v18 HISTOR 14,933/14,933。候选19 HISTOR 为 407 HC／6327 any／5920 advisory-only，已发布 WARDEN 为 409／6327／5918。HISTOR 上 v18→v19 零判定变化。对 v17 后允许的两段文本作窄范围审查，确认它们描述正常公钥配置：`@krovacloud/mcp@0.3.16` 的 `create_cube`／`sshPublicKey`，以及 `@runpod/mcp-server@4.4.0` 的 `update-ssh-keys`／`keys`。这只评价这些片段，不认证整个包安全；不再分发原始文本。

Author35 和 independent12 是混合组，阈值阳性总数不是召回率；应分别使用 23/12 和 10/1/1 标签。真实互操作属于候选19证据，不填进五产品分类表。

## 候选验证与来源范围

更早 v18 两主机各 1,517/1,517 测试、62 文件，typecheck/build 通过；独立 red-team 0/28 delivered，不代表五产品模型攻击成功率。整个目录见证因相邻报告脚本修改而不完整；实际产品及 1,090 个已捕获 source/test/script 文件稳定。

候选19 两台主机均 **63 文件、1,536/1,536 测试通过**，typecheck/build/red-team 退出码 0、无 OOM；attested 288.085 秒，PingBlip 558.354 秒。1,534 检测器测试先已通过，旧 README/landing 计数导致重试。验证副本只改五份 README 计数，不改检测器；521 runtime/source/test 文件逐字节相同，digest `f4732e8beb77342ae250ac11126859ef59cf5e9bf3d74e8e46221b8d856d3231`。范围是冻结候选，不代表整个工作区；保留初始诊断及已中断的旧 Blip 尝试。

## 后续运行时构件 .2

`0.23.1-dev.20261107.2` 与冻结 `.1` 分开：接受缺少可选 `mimeType` 的有效 MCP blob-resource，同时继续扫描相似 metadata/structured 对象。两主机均 **63 文件、1,536/1,536 测试通过**，typecheck/build/red-team 退出0；attested 293.705 秒，PingBlip 554.284 秒。正常 1 CPU、原期限下 304 专项测试通过，SDK 8/8 会话和 4/4 列表配对通过。保留早期 0.25 CPU 设置超时，正常配置未再现。

独立 binary/SDK 检查保留 400k 有效 blob 的字节，有无 MIME 均可。无效 plaintext/object-blob/poisoned-metadata 结果在执行一次后被隐藏、会话仍活；这是结果筛选兼容性，不代表阻止工具副作用。23 个代表性 CLI/library 检查的 `.1`/`.2` 发现和 score 一致。变更的 result-screen 模块之外，320 个源码／分发文件与 `.1` 逐字节相同，SHA-256 `5ff407cf78742ae18fd593065e9c9bd552bba45f3fab91f27fae9f45adb13238`，rules19 digest 不变。18,110 行分类仍是 `.1` 实测，不改称 `.2`；两者源码仍未发布。

当前工作快照 `0.23.1-dev.20261108` 添加冻结 `.1`、`.2` 中没有的 Codex/OpenCode hooks，其验收验证单独进行。18,110 行分类和冻结构件质量凭据不被当作 11 月 8 日新增内容的测量。

## 结论范围

自编样例由 WARDEN 作者编写，第三方样例在开发期间已被阅读。MCPTox test 是 **已知的历史留出集**，不是新获得的未见测试集：结果多次公布，并且与 dev 共用攻击模板。重新运行不能恢复盲测。声称后续规则未使用测试输入，需要保留来源审计；仅无相同短语不能证明独立性。

归档不证明服务器当前行为。发现不测试工具执行或依赖安全。静态阻止不测量模型攻击成功率、端到端防护或防止数据外泄。若另做模型实验，须单独记录模型／版本、提示、预算、请求证据与分母；本文静态表格不包含这些结论。
