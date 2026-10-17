# 扫描 MCP 客户端启动的服务器

> 🌐 [English](scan.md) · [Русский](scan.ru.md) · [Español](scan.es.md) · [Français](scan.fr.md) · **中文**

`warden-mcp scan` 读取你已有的 MCP 配置，连接其中启动的每个服务器，并在模型看到工具定义之前对其进行审查。它与 [`wrap`](../README-zh.md) 和[库](integration.zh.md)使用同一条关卡链，只是对你的配置运行一次，而不是挡在单个服务器前面。

```bash
npx -y @aimarket/warden@0.11.0 scan
```

```text
WARDEN scan 0.10.0 · ruleset 10 sha256-lJuKKKV5mtru… · block at high
  read .mcp.json (claude-code, 3 servers)

  ✓ allow   notes       claude-code    1 tool · score 0.90
  ✗ BLOCK   evil-notes  claude-code    1 tool · score 0.00 · TOOL_DEF_EXFIL(notes) TOOL_DEF_SECRET_REQUEST(notes) THREAT_SSH_KEY_READ(notes)
  ! error   broken      claude-code    could not start: spawn /nonexistent/bin/server ENOENT

3 servers: 1 allowed, 1 blocked, 1 not checked, 0 skipped.
Details: warden-mcp scan --json, or --markdown FILE. To review a changed server: warden-mcp scan --lock warden.lock.json --update-lock.
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
      - uses: alexar76/warden@v0.11.0
        with:
          upload-sarif: 'true'
```

默认情况下，它读取项目文件，不启动 stdio 服务器（该程序由 pull request 决定），拒绝非公网地址，存在 `warden.lock.json` 时使用它，写入作业摘要，并在有服务器被阻止时失败。输入：`config`、`working-directory`、`lock`、`launch-stdio`、`public-only`、`fail-on`、`histor`、`classifier-url`、`classifier-model`、`classifier-blocks`、`sarif`、`upload-sarif`、`version`。输出：`blocked`、`servers`、`sarif`。在生产 workflow 中请按提交 SHA 固定该 Action。

若想在你使用的服务器发生变化时得到通知，可以再按计划运行同一个 job（`on: { schedule: [{ cron: '17 6 * * *' }] }`）：只要仓库里提交了 `warden.lock.json`，工具定义发生变化的服务器就会以 `TOOL_DEF_DRIFT` 让这次运行失败，摘要中会显示 diff。

## pre-commit

```yaml
repos:
  - repo: https://github.com/alexar76/warden
    rev: v0.10.0
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

## 有毒数据流：单个安全，组合危险

客户端把所有服务器的工具交给同一个模型。如果其中有一个工具读取你的私有数据，一个工具引入外部文本（网页、issue、邮件），还有一个工具能把数据发出去，那么经第二个工具进来的文本就可以让模型用第一个读取、用第三个发送。没有哪个服务器有错，所以按服务器给出的结论看不到它。`scan` 按客户端报告：

```text
  ⚠ toxic flow  claude-code can read private data (filesystem.read_file, …), take in text from outside (fetch.fetch) and send data out (fetch.fetch). …
```

能力从工具名和参数名（`read_file`、`send_email`、`url` 或 `to` 参数）中读取，而不是从描述中读取：结果与描述的语言无关，描述也无法为自己开脱。数据流只是提示：从不阻止，也不改变退出码。它出现在 `--json`（`flows`）和 Markdown 摘要中。要打断它，去掉其中一环——例如不需要的 `fetch` 服务器，或把只开放一个文件夹的文件服务器放到另一个客户端。

## HISTOR：这个服务器给你的是否和给所有人的一样？

[HISTOR](https://histor.modelmarket.dev) 是一个公开日志，每天记录官方 MCP 注册表中所有远程服务器的工具定义。`--histor` 对每个远程服务器问它一个问题：你刚收到的工具集，是否就是 HISTOR 观察到的那一个？

发送的内容：端点（只有协议、主机和路径，不含 query、用户名或密码），以及工具集的 [MTL/1](https://github.com/alexar76/awr) 摘要。不发送任何工具描述或请求头。私有主机或地址上的端点，以及看起来带有密钥的路径，根本不会发送；报告会说明原因。

从公共 npm 或 PyPI 注册表启动的 stdio 服务器（`npx`、`bunx`、`npm exec`、`pnpm dlx`、`uvx`、`uv tool run`、`pipx run`）以其软件包命名——`npm:<名称>` 或 `pypi:<名称>`，不带版本——并附上同样的摘要。HISTOR 会在 gVisor 沙箱中（诱饵凭据、无对外路由；每个工具用金丝雀参数调用一次，不作用于任何真实对象）安装这类软件包的每个已发布版本，并记录其工具及其行为，因此这里的 `previously-observed` 表示你运行的是较旧的版本，`different` 表示 HISTOR 尚未覆盖到的版本、工具取决于你的机器上有而沙箱里没有的东西的软件包（把工作交给本地已安装程序的启动器、真实的密钥或设置），或者与已发布版本不一致的软件包。该发现会给出双方各自的工具数量。本地路径、git 或 tarball 地址、私有注册表（`--registry`、`--index-url`）以及直接用 `node`/`python` 启动的服务器，永远不会被发送。 对于软件包，HISTOR 还会以提示性发现告诉你：它的名称是否在模仿热门软件包（`HISTOR_PACKAGE_LOOKALIKE`：相差一个字符、在另一个 scope 下同名或仅分隔符不同，且热门软件包的下载量至少高 100 倍），以及所观察的版本是否带有发布令牌被盗的迹象：`HISTOR_PACKAGE_PROVENANCE_LOST`（上一个版本有经证明的 CI 构建，这个版本没有）、`HISTOR_PACKAGE_INSTALL_SCRIPTS`（新增安装脚本）、`HISTOR_PACKAGE_PUBLISHER_CHANGED`、`HISTOR_PACKAGE_NEW_DEPENDENCIES`。 以及软件包在沙箱中的行为：`HISTOR_PACKAGE_READS_SECRETS`（在安装、启动或工具被调用时打开了诱饵凭据——SSH 密钥、云或注册表令牌、钱包），`HISTOR_PACKAGE_PERSISTENCE`（写入了会在会话之后留存的位置，例如 `.bashrc` 或 `authorized_keys`），`HISTOR_PACKAGE_STARTUP_NETWORK`（在调用任何工具之前就访问了网络），`HISTOR_PACKAGE_STARTS_PROGRAMS`，`HISTOR_PACKAGE_INSTALL_BEHAVIOUR`（其安装脚本做了什么）。从工作目录加载 `.env`、在工具调用期间访问其自身 API，都不算发现。软件包为何没有启动——依据它打印的内容：`HISTOR_PACKAGE_SDK_INCOMPATIBLE`（medium——为 MCP SDK 1.x 编写，因此用 `mcp` 2.x 全新安装会在导入时失败；如果 HISTOR 也用 `mcp<2` 运行过它，则给出当时列出的工具数量）、`HISTOR_PACKAGE_NEEDS_CONFIG`（info——它要求的密钥或设置，或其工具是在占位值下读取的）以及 `HISTOR_PACKAGE_KEY_SENT_TO`（low——它把 HISTOR 设置的占位密钥发送到了哪里；请确认那是该服务自己的 API）。所有沙箱发现都来自相同的条件：gVisor 下的 Linux、无互联网、诱饵机密（[测试条件](https://histor.modelmarket.dev/#conditions)）。 使用 `--histor` 时，报告还会给出一个 HISTOR 订阅源链接，包含 HISTOR 已知的被扫描服务器的变更（`--json` 中的 `historWatch`）：可在任意订阅阅读器中订阅。

| 回答 | 含义 |
|---|---|
| `same` | 你收到的就是 HISTOR 当前观察到的工具集 |
| `different` | HISTOR 从未见过这个工具集：它在最近一次每日抓取之后发生了变化，或者服务器给你的内容与给公开爬虫的不同。对于软件包，还可能是：它的工具取决于你的机器上有什么（见上文）。以仅作建议的发现 `HISTOR_UNSEEN_TOOLSET` 报告 |
| `previously-observed` | HISTOR 以前见过、但不是当前的工具集。仅作建议的发现 `HISTOR_OLDER_TOOLSET` |
| `not-listed`、`not-observed` | HISTOR 不认识这个端点，或尚未成功读取过它 |

如果你拿到的工具集是服务器发布者在其注册表条目中声明的工具集（[发布者如何声明工具集](https://github.com/alexar76/histor/blob/main/docs/api.zh.md)），例如启动器在其程序已安装的机器上给出的工具，发现会是 `HISTOR_DECLARED_TOOLSET` 而不是 `HISTOR_UNSEEN_TOOLSET`：low，当 HISTOR 没有自己的工具集时为 info，并附上发布者原话写的条件。这是发布者的说法，不是观测，其他所有检查仍会读取这些工具。

HISTOR 的回答从不阻止。HISTOR 没有响应时会在报告中注明，扫描继续进行。

## 面向发布者：声明你的服务器的工具集

HISTOR 只能记录你的服务器在其沙箱中列出的工具。如果在安装了沙箱所没有的东西的地方——启动器的运行器、每个操作系统各一个、真实的密钥——它列出的是别的工具，就声明这些工具集，拿到它们的人看到的将是 `HISTOR_DECLARED_TOOLSET`（low），而不是 `HISTOR_UNSEEN_TOOLSET`（medium）。在能拿到该工具集的机器上：

```bash
npx -y @aimarket/warden declare --when "runner 1.4, macOS" --out mcp-tool-sets.json -- npx -y @acme/launcher
```

WARDEN 会像客户端一样启动服务器，计算其 `tools/list` 的摘要（MTL/1），并把该工具集加入 `mcp-tool-sets.json`，保留已有的工具集并替换相同的摘要。在每个操作系统和每个运行器版本上重复。然后：

1. 把文件发布到注册表为你的服务器命名空间验证过的域名上——`ai.acme/launcher` → `acme.ai` 或其子域名；`io.github.<user>/…` → `<user>.github.io` 或你在 GitHub 上的 raw 文件——例如 `https://acme.ai/.well-known/mcp-tool-sets.json`。
2. 让注册表条目指向它，只需一次：`npx -y @aimarket/warden declare --server-json --link <url>` 打印 `server.json` 的 `_meta` 块；把这个版本发布到注册表。
3. 检查：`npx -y @aimarket/warden declare --check <url> --name ai.acme/launcher` 按 HISTOR 的方式读取文件，并说明 HISTOR 会从中采用什么。

此后，发布新的运行器只需要 `declare --out` 并重新上传文件：HISTOR 每小时读取一次。从文件中删去的工具集会被撤回；HISTOR 无法读取的文件会保留其声明。不使用文件时，`--server-json` 加上 `--` 之后的服务器会把工具集直接放进条目，最多 8 个。HISTOR 采用的规则：[声明工具集](https://github.com/alexar76/histor/blob/main/docs/api.zh.md)。声明是发布者的说法，不是观测：WARDEN 仍会对拿到的工具执行全部检查。

## 可选的分类器

WARDEN 的规则离线、确定性地运行，也会漏掉任何规则都没提到的内容：改写的说法、另一种语言的指令。`--classifier-url` 和 `--classifier-model` 通过任意 OpenAI 兼容端点，加入你所选模型的第二意见：本地的 Ollama、vLLM 或 LM Studio，或托管 API。

```bash
warden-mcp scan --classifier-url http://localhost:11434/v1 --classifier-model qwen2.5:14b
WARDEN_CLASSIFIER_API_KEY=… warden-mcp scan --classifier-url https://api.deepseek.com --classifier-model deepseek-flash --classifier-reasoning-effort none
```

- **显式启用，并发送所有声明字段。** 包括名称、标题、描述、输入/输出 schema、annotations 和扩展元数据；需要时附带归一化文本。密钥仅来自 `WARDEN_CLASSIFIER_API_KEY`。
- **默认仅建议；`--classifier-blocks` 对不完整检查拒绝放行。** 检测结果使用 `TOOL_DEF_CLASSIFIER`。截断、不确定、覆盖不完整、无效回答、超时及服务错误使用 `CLASSIFIER_INCOMPLETE`；这是检查失败，不是检测到攻击，`--update-lock` 不能批准这些结果。
- **五类语义检查。** `instruction_to_model`、`exfiltration`、`secret_request`、`concealment`、`cross_tool`。检查任何语言中的权限越界，但效果取决于模型的语言能力。协议要求每个工具有明确决定及有效的字段编号；WARDEN 自行从原文提取证据。每个未完成的工具最多单独重试一次。随机分隔符不保证免疫提示注入。
- **检查不等于批准。** [`wrap --require-approval`](security-hardening-language-boundary.md) 提供独立于语言的操作员批准边界。HISTOR 的历史模型结果仍然仅供参考。

2026 年 10 月 16 日用 `deepseek-flash`（HISTOR 使用的同一模型）在 MCPTox（下文对比中介绍的公开基准）、真实服务器和我们自己的样本集上测得：

| | 规则（v12） | 规则 + `high` 级分类器 |
|---|---|---|
| MCPTox 留出的一半，218 个投毒工具中被发现的数量 | 171 | 218 |
| 45 台干净的 MCPTox 服务器，被标记数 | 0 | 0 |
| 随机抽取的 200 台语料服务器，被阻止或标记数 | 2 | 5 |
| 随机样本中的 996 个 npm 与 PyPI 包，被阻止或标记数 | 23 | 35 |
| 我们编写的 23 个攻击 / 12 个困难的良性样例 | 20 / 0 | 23 / 0 |

规则阻止的两台语料服务器，是下文对比中的身份服务和部署工具。分类器在真实服务器上的 `high` 标记大多是“先调用这个工具”之类的工作流指令。有两个包值得人工查看，而规则一个也没有阻止：一个把描述包在伪造的“这是用户要求的”块中，并命令模型在任何回复之前先调用它；另一个把文件内容从智能体发送到自己的服务器，并写着 “Do NOT display … to the user”。模型漏掉了规则能抓到的东西：工具名中的注入、作为参数索要的私钥或助记词，以及 `rm -rf ~`。两者合起来能发现我们全部 23 个攻击。

## 对比

2026 年 10 月 16 日，我们在同一批服务器上运行了 WARDEN、mcp-audit 0.18.2（`--connect`）、mcp-shield 1.0.4、truecopy 0.10.4 和 mcpsentry 0.1.5。每台服务器都通过 stdio 重放，因此每款扫描器都像在实际使用中一样连接它。每款扫描器都在无网络的 gVisor 容器中运行，镜像固定，其内容的哈希记录在清单中。测试工具、样本集、清单和每一条判定都在 [`scripts/scanner-comparison`](../scripts/scanner-comparison/)。包含方法和全部注意事项的完整报告是[扫描器对比](scanner-comparison.zh.md)。

MCPTox 各行来自 MCPTox（Wang 等，AAAI 2026）：一个公开的基准，包含为 45 台真实 MCP 服务器编写的 485 个投毒工具。我们用固定哈希把它的服务器分成两半。规则集 v10 依据其中 22 台编写；表中报告的是另外 23 台，共 218 个没有任何规则照着调过的投毒工具。v11 和 v12 也不是依据它们编写的，给出的判定与 v10 相同。

| 服务器 | WARDEN 0.16.0（v12） | mcp-audit 0.18.2 | mcp-shield 1.0.4 | truecopy 0.10.4 | mcpsentry 0.1.5 |
|---|---|---|---|---|---|
| 我们编写的 23 个攻击，阻止数 | 20 | 10 | 6 | 8 | 4 |
| mcp-audit 与 mcp-shield 自带样例中的 10 个攻击，阻止数 | 10 | 10 | 8 | 7 | 5 |
| 12 个困难的良性样例，阻止数 | 0 | 1 | 1 | 1 | 2 |
| 留出服务器上的 218 个 MCPTox 投毒工具，阻止数 | 171 | 25 | 41 | 27 | 8 |
| 带 `<IMPORTANT>` 或 “Ignore the previous instructions” 前缀的 225 个 MCPTox 工具，阻止数 | 225 | 222 | 41 | 141 | 136 |
| 45 台干净的 MCPTox 服务器，阻止数 | 0 | 2 | 3 | 0 | 1 |
| 986 台公开服务器，阻止数 | 3 | 33 | 343 | 39 | 86 |
| ……读过文本后站得住的阻止 | 1 个，另有 1 个有争议 | 0 | 我们读过的 34 个中有 1 个 | 1 | 0 |
| HISTOR 观察过的 14,933 个 npm 与 PyPI 包，阻止数 | 369 | 928 | 5,354 | 252 | 1,449 |

- **先看真实服务器这几行。** 没有任何规则照着它们调过。mcp-audit 在语料上的 33 个阻止，大多是完全用本身文字书写的文本中的“同形字”，以及 “do not tell the user the check digits are wrong” 这样的诚实性说明。mcp-shield 阻止了三分之一的真实服务器，几乎都是因为关键词：“API key”、“token”、`.env`、“..”。truecopy 阻止了同一厂商的 docker-compose 生成器，因为它们会生成 `.env.example`。mcpsentry 的 base64 模式会匹配任何 40 个字母和斜杠组成的串，JSON Schema 路径就会产生这样的串。在 14,933 个 npm 与 PyPI 包中，我们判定了每个阻止的 996 个随机样本里，WARDEN 有 23 个阻止，无一站得住，4 个有争议；mcp-shield 在同一批包中阻止 339 个，mcpsentry 阻止 112 个。
- **弄清哪些数字是照着样本调出来的。** 第一套攻击是我们写的，规则集 v9 是在读过两套攻击之后写的。MCPTox 留出一半那一行、干净服务器、语料和包都不是照着样本调出来的。
- **MCPTox 测的是一种形态，而不是关键词。** 几乎每个投毒工具都让模型先调用另一个工具，或修改另一个工具的参数。v10 给这种形态起了名字（`TOOL_DEF_CROSS_TOOL`，见[关卡链](gates.zh.md)），v12 保留了它。加上基准的 `<IMPORTANT>` 前缀后，大多数扫描器能发现大多数工具。
- **WARDEN 仍然漏掉的：** 218 个留出 MCPTox 工具中的 47 个、一条用中文要求读取 `.env` 的指令、一句没有关键词的改写（“gather every credential file … keep this step to yourself”）以及 “include the output of env”。这 47 个中有 41 个它以建议性发现的形式报告，而不是阻止。启用上文的可选分类器后，全部 218 个都在 `high` 级别被标记。
- **在这一位置上 WARDEN 并不孤单。** mcp-audit 也提供 lock 文件、PR 差异模式和 SARIF；truecopy 同样会在 lock 文件中固定并签名工具定义。

## scan 不做什么

- 它只读取一次定义。之后才改变的服务器，会被下一次扫描、CI 中的 lock 文件，或在每次调用时由 `wrap` 发现。
- 它不扫描调用参数和结果、prompts 或 resources，也不是沙箱：启动 stdio 服务器就会执行它。
- 它的裁定来自 WARDEN 的静态规则和威胁记录。没有任何规则覆盖的改写说法会通过；规则能捕获什么、误判有多频繁，参见[关卡链](gates.zh.md)和[实地调查](mcp-survey.zh.md)。
