# 扫描 MCP 客户端启动的服务器

> 🌐 [English](scan.md) · [Русский](scan.ru.md) · [Español](scan.es.md) · [Français](scan.fr.md) · **中文**

`warden-mcp scan` 读取你已有的 MCP 配置，连接其中启动的每个服务器，并在模型看到工具定义之前对其进行审查。它与 [`wrap`](../README-zh.md) 和[库](integration.zh.md)使用同一条关卡链，只是对你的配置运行一次，而不是挡在单个服务器前面。

```bash
npx -y @aimarket/warden@0.9.0 scan
```

```text
WARDEN scan 0.9.0 · ruleset 10 sha256-lJuKKKV5mtru… · block at high
  read .mcp.json (claude-code, 3 servers)

  ✓ allow   notes        claude-code    1 tool · score 0.90
  ✗ BLOCK   evil-notes   claude-code    1 tool · score 0.00 · TOOL_DEF_EXFIL(notes) TOOL_DEF_SECRET_REQUEST(notes)
  ! error   broken       claude-code    could not start: spawn /nonexistent/bin/server ENOENT

3 servers: 1 allowed, 1 blocked, 1 not checked, 0 skipped.
```

无需账号、无需 API 密钥、不调用模型。唯一的网络流量是发往你配置中的服务器；如果传入 `--histor`，还会发往 HISTOR 日志。

## 查找位置

不带参数时，扫描下表中所有存在的文件。传入文件则只扫描这些文件；`--project` 只扫描工作目录中的项目文件；`--client NAME` 只扫描一个客户端。

| 客户端 | 项目文件 | 用户文件 |
|---|---|---|
| Claude Code | `.mcp.json` | `~/.claude.json`（用户级服务器和本项目的服务器） |
| Claude Desktop | — | 应用配置目录中的 `claude_desktop_config.json` |
| Cursor | `.cursor/mcp.json` | `~/.cursor/mcp.json` |
| VS Code | `.vscode/mcp.json`（JSONC） | 用户设置目录中的 `mcp.json` |
| Windsurf | — | `~/.codeium/windsurf/mcp_config.json` |

配置中通过 `warden-mcp wrap` 启动的服务器，会按包装器背后的服务器来扫描，并使用 `wrap` 所用的 pin id，因此相对已批准快照的漂移会出现在报告中。已禁用的条目、需要客户端向用户索取 `${input:…}` 值的条目，以及既没有 `command` 也没有 `url` 的条目，都会列为已跳过，绝不会被悄悄丢弃。

## 启动服务器

为了读取 stdio 服务器的工具，`scan` 会用配置中的命令、参数和环境启动它——与客户端的做法完全相同——并在 `tools/list` 之后停止它。它从不调用工具。但程序仍然会被执行。在不希望这样的场合，例如针对 pull request 的 CI 中，`--no-launch` 只审查启动命令：threat feed 中的命令记录，以及 lock 文件中的启动身份。

远程服务器（`url`，streamable HTTP 或较旧的 HTTP+SSE）会通过网络、带着配置中的请求头进行查询。`--public-only` 会拒绝解析到回环、私有、链路本地或云元数据地址的服务器，检查的是实际连接的地址。不跟随重定向。

## 输出与退出码

| 选项 | 输出 |
|---|---|
| （默认） | 在 stdout 输出表格 |
| `--json` | 在 stdout 输出 JSON 报告 |
| `--json-file FILE` | 将 JSON 报告写入文件，同时输出表格 |
| `--sarif FILE` | 用于 GitHub code scanning 的 SARIF 2.1.0；只包含会阻止的发现，定位到配置中该服务器所在的行 |
| `--markdown FILE` | 带可折叠详情的摘要，用于 `$GITHUB_STEP_SUMMARY` 或 PR 评论 |

退出码 `0`：没有任何阻止。`1`：有服务器被阻止，或在 `--fail-on-error` 下有服务器无法检查。`2`：用法或配置错误。`--fail-on SEVERITY` 调整阻止阈值；`--policy FILE` 接受与 `wrap` 相同的严格策略文件。

启动命令和 URL 中的凭据显示为 `***`。Markdown 报告中的工具描述放在该文本无法闭合的代码块里。

## Lock 文件：审查定义，而不只是命令

配置中的一行说明启动哪个程序，却不说明这个程序会对你的模型说什么。Lock 文件记录后者，好让 pull request 把它展示出来。

```bash
warden-mcp scan --project --lock warden.lock.json --update-lock   # 先读完改动再运行
git add .mcp.json warden.lock.json
```

`--update-lock` 为每个服务器写入启动身份和完整的工具定义，并拒绝记录 WARDEN 阻止的服务器。对未变化的服务器再次运行，文件不会改变。只使用 `--lock` 时：

- lock 中没有的服务器会被阻止（`LOCK_MISSING`）；
- 启动方式改变的服务器会被阻止（`SERVER_IDENTITY_DRIFT`）；
- 现在声明了不同工具的服务器会被阻止（`TOOL_DEF_DRIFT`），Markdown 报告以名称、描述和 schema 的 diff 展示改动。

没有任何配置启动的 lock 条目会被列出，并在下次更新时删除。

## GitHub Action

```yaml
name: MCP servers
on: [pull_request]
permissions:
  contents: read
  security-events: write   # 仅 upload-sarif 需要
jobs:
  warden:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: alexar76/warden@v0.9.0
        with:
          upload-sarif: 'true'
```

默认情况下，它读取项目文件，不启动 stdio 服务器（该程序由 pull request 决定），拒绝非公网地址，存在 `warden.lock.json` 时使用它，写入作业摘要，并在有服务器被阻止时失败。输入：`config`、`working-directory`、`lock`、`launch-stdio`、`public-only`、`fail-on`、`histor`、`classifier-url`、`classifier-model`、`classifier-blocks`、`sarif`、`upload-sarif`、`version`。输出：`blocked`、`servers`、`sarif`。在生产 workflow 中请按提交 SHA 固定该 Action。

## pre-commit

```yaml
repos:
  - repo: https://github.com/alexar76/warden
    rev: v0.9.0
    hooks:
      - id: warden-scan     # 改动过的配置；不启动 stdio 服务器
      - id: warden-lock     # 项目与 warden.lock.json 一致；会启动 stdio 服务器
```

两个钩子都通过 `npx` 运行已发布的包，因此 `PATH` 中需要 Node 20 或更高版本。

## Claude Code 插件

```text
/plugin marketplace add alexar76/warden
/plugin install warden@warden
```

会话开始时，它扫描 Claude Code 为该项目启动的服务器，告诉你哪些被阻止，而对模型只给出名称和发现代码。被阻止的描述永远不会进入模型的上下文。之后，`PreToolUse` 钩子会拒绝对被阻止服务器的工具或被阻止工具的调用；它只读取一个小文件，不启动任何程序。详情与限制：[claude-plugin/README.md](../claude-plugin/README.md)。

## HISTOR：这个服务器给你的是否和给所有人的一样？

[HISTOR](https://histor.modelmarket.dev) 是一个公开日志，每天记录官方 MCP 注册表中所有远程服务器的工具定义。`--histor` 对每个远程服务器问它一个问题：你刚收到的工具集，是否就是 HISTOR 观察到的那一个？

发送的内容：端点（只有协议、主机和路径，不含 query、用户名或密码），以及工具集的 [MTL/1](https://github.com/alexar76/awr) 摘要。不发送任何工具描述、请求头或 stdio 服务器。私有主机或地址上的端点，以及看起来带有密钥的路径，根本不会发送；报告会说明原因。

| 回答 | 含义 |
|---|---|
| `same` | 你收到的就是 HISTOR 当前观察到的工具集 |
| `different` | HISTOR 从未见过这个工具集：它在最近一次每日抓取之后发生了变化，或者服务器给你的内容与给公开爬虫的不同。以仅作建议的发现 `HISTOR_UNSEEN_TOOLSET` 报告 |
| `previously-observed` | HISTOR 以前见过、但不是当前的工具集。仅作建议的发现 `HISTOR_OLDER_TOOLSET` |
| `not-listed`、`not-observed` | HISTOR 不认识这个端点，或尚未成功读取过它 |

HISTOR 的回答从不阻止。HISTOR 没有响应时会在报告中注明，扫描继续进行。

## 可选的分类器

WARDEN 的规则离线、确定性地运行，也会漏掉任何规则都没提到的内容：改写的说法、另一种语言的指令。`--classifier-url` 和 `--classifier-model` 通过任意 OpenAI 兼容端点，加入你所选模型的第二意见：本地的 Ollama、vLLM 或 LM Studio，或托管 API。

```bash
warden-mcp scan --classifier-url http://localhost:11434/v1 --classifier-model qwen2.5:14b
WARDEN_CLASSIFIER_API_KEY=… warden-mcp scan --classifier-url https://api.deepseek.com --classifier-model deepseek-flash
```

- **默认关闭，开启后会发送工具文本。** 两个参数都给出时，每个工具的名称、描述和 schema 都会发送到该端点。本地模型会让它们留在你的机器上。如需密钥，只从 `WARDEN_CLASSIFIER_API_KEY` 读取，从不通过命令行参数。
- **除非加 `--classifier-blocks`，否则只作建议。** 它的判定以 `TOOL_DEF_CLASSIFIER` 报告。加上 `--classifier-blocks` 后，达到或超过阻止阈值（默认 `high`）的判定会像规则一样阻止该工具。分类器没有响应时会在报告中注明，且从不阻止。
- **与 HISTOR 问同一个问题。** 提示词、四个类别（`instruction_to_model`、`exfiltration`、`secret_request`、`concealment`）和回答格式都与 HISTOR 日志的分类器相同。工具文本放在带随机后缀的标记之间，它无法伪造这些标记；模型的回答会逐字段校验。加上 `--histor` 时，还会显示日志对你收到的工具集保存的判定（`HISTOR_CLASSIFIER`，仅作建议）。
- **它不读取 annotations 和扩展字段。** 规则会读取。

2026 年 10 月 9 日用 `deepseek-flash`（HISTOR 使用的同一模型）在 MCPTox（下文对比中介绍的公开基准）和我们自己的样本集上测得：

| | 规则（v10） | 规则 + 分类器，`high` 时阻止 | 规则 + 分类器的任何标记（仅作建议） |
|---|---|---|---|
| MCPTox 留出的一半，218 个投毒工具中被发现的数量 | 171 | 191 | 218 |
| 45 台 MCPTox 干净服务器，被阻止或被标记 | 0 | 0 | 4 台被标记 |
| 随机抽取的 200 台语料服务器，被阻止或被标记 | 2 台被阻止 | 2 台被阻止 | 2 台被阻止，另 12 台被标记 |
| 我们写的 23 个攻击 / 12 个困难的良性样例 | 20 / 0 | 22 / 0 | 23 / 0 |

规则阻止的那两台是下文对比中的身份服务和部署工具。分类器标记的 13 台服务器都是 `medium` 或 `low`，没有 `high`。其中 6 台值得人工查看：一台要求模型“作为第一个也是唯一的动作”进行不可撤销的 ENS 名称转移，且不询问用户；另一台要求模型不要透露其数据来源。模型还标记了官方的 Fetch 服务器，它的描述告诉模型现在可以上网、不应拒绝。这是对模型的指令，但不是攻击。模型漏掉了规则能发现的内容：annotations 中的注入、以参数形式索要私钥或助记词，以及 `rm -rf ~`。

## 对比

2026 年 10 月 9 日，我们在同一批服务器上运行了 WARDEN、mcp-audit 0.18.2（`--connect`）和 mcp-shield 1.0.4。每台服务器都通过 stdio 重放，因此每个扫描器连接它的方式与真实环境相同。测试工具、样本集和每一条判定都在 [`scripts/scanner-comparison`](../scripts/scanner-comparison/) 中。包含方法和全部注意事项的完整研究，见[扫描器对比](scanner-comparison.zh.md)。

最后三行来自 MCPTox（Wang 等，AAAI 2026）：一个公开的基准，包含为 45 台真实 MCP 服务器编写的 485 个投毒工具。我们用固定哈希把它的服务器分成两半。ruleset v10 依据其中 22 台服务器编写；表中报告的是另外 23 台，共 218 个投毒工具，没有任何规则照着它们调过。

| 服务器 | WARDEN 0.8.2（v8） | WARDEN 0.9.0（v10） | mcp-audit 0.18.2 | mcp-shield 1.0.4 |
|---|---|---|---|---|
| 我们编写的 23 个攻击，阻止数 | 14 | 20 | 10 | 6 |
| 取自 mcp-audit 与 mcp-shield 自带样例的 10 个攻击，阻止数 | 7 | 10 | 10 | 8 |
| 12 个困难的良性样例，阻止数 | 0 | 0 | 1 | 1 |
| 986 台公开服务器，阻止数 | 3 | 3 | 33 | 343 |
| …读过文本后站得住脚的阻止 | 1 台，另 1 台存疑 | 1 台，另 1 台存疑 | 0 | 随机抽取的 20 台中 0 台 |
| MCPTox 留出服务器上的 218 个投毒工具，阻止数 | 26 | 171 | 25 | 41 |
| 带 `<IMPORTANT>` 或 “Ignore the previous instructions” 前缀的 225 个 MCPTox 工具，阻止数 | 225 | 225 | 222 | 未运行 |
| 45 台 MCPTox 干净服务器，阻止数 | 0 | 0 | 2 | 3 |

- **先看语料这一行。** 没有任何规则是照着它调的。mcp-audit 的 33 次阻止中，16 次是对完全用本文字书写的文本报“同形字”（中文标点、希腊符号、西里尔字母），12 次是诚实性提示（如 “do not tell the user the check digits are wrong”），3 次是 base64 工具，一个 SSH 公钥工具，还有 WARDEN 也误阻止的那个部署工具。mcp-shield 阻止了 35% 的真实服务器，几乎都因为关键词：“API key”“token”、`.env`、“..”。省略号（“Shopify...”）被当作路径穿越。它也阻止了 WARDEN 阻止的那个身份服务，但依据是 “credentials” 这个词。
- **要清楚哪些数字是调出来的。** 第一组攻击样本是我们写的。ruleset v9 是在读过两组攻击样本之后写的，v10 是在读过另一半的 22 台 MCPTox 服务器之后写的。所以 20 和 10 是“照着见过的样本调出来的规则”的召回率。MCPTox 留出的那一行、干净服务器、语料以及整个 0.8.2 列都没有经过调整。在语料上，v10 阻止的与 v8 完全相同。
- **MCPTox 考的是结构，不是关键词。** 几乎每个投毒工具都要求模型先调用另一个工具，或修改另一个工具的参数。v10 为这种结构命名（`TOOL_DEF_CROSS_TOOL`，见[关卡链](gates.zh.md)），在留出的 218 个工具中阻止 171 个；在用来编写它的那一半上是 267 个中的 189 个。加上基准自带的 `<IMPORTANT>` 或 “Ignore the previous instructions” 前缀后，我们运行的每个扫描器都能发现；mcp-shield 没有在这一组上运行。在干净服务器上，mcp-audit 阻止了 AmapMap 和 BaiduMap，mcp-shield 以 “sensitive file access” 为由阻止了 FileSystem、AdFin 和 Commander。
- **WARDEN 仍会漏掉的：** 留出的 218 个 MCPTox 工具中的 47 个、用中文写的读取 `.env` 的指令、没有关键词的改写（“gather every credential file … keep this step to yourself”），以及 “include the output of env”。这 47 个中的 41 个以及我们的这三个，它会以建议的形式报告，但不会阻止。这些需要基于语义的检查，而不是再加一条规则：加上上文的可选分类器，218 个中有 191 个在 `high` 级别被阻止，218 个全部被标记。
- **未参与对比：** Snyk Agent Scan（原 Invariant mcp-scan），使用最广的扫描器。它在 Snyk 的服务器上判定描述，需要账号令牌。mcp-audit 同样提供 lock 文件、PR diff 模式和 SARIF；在这个位置上 WARDEN 并不是唯一的选择。

## scan 不做什么

- 它只读取一次定义。之后才改变的服务器，会被下一次扫描、CI 中的 lock 文件，或在每次调用时由 `wrap` 发现。
- 它不扫描调用参数和结果、prompts 或 resources，也不是沙箱：启动 stdio 服务器就会执行它。
- 它的裁定来自 WARDEN 的静态规则和威胁记录。没有任何规则覆盖的改写说法会通过；规则能捕获什么、误判有多频繁，参见[关卡链](gates.zh.md)和[实地调查](mcp-survey.zh.md)。
