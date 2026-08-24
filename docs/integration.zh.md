# 集成指南

> 🌐 [English](integration.md) · [Русский](integration.ru.md) · [Español](integration.es.md) · [Français](integration.fr.md) · **中文**

WARDEN 是一个库，不是代理。你只在自己 MCP 宿主生命周期中的某一个点调用它：在服务器告诉你它能做什么之后，在把这些
告诉模型之前。

```
connect ──► listTools ──► warden.vet() ──► 把 allowedTools 暴露给模型
                              │                    │
                              │                    └─► 每次调用：isSensitiveTool → 询问用户
                              └─► 被阻止：断开连接，并把裁定记录下来
                                             一次批准后：warden.approve() 固定这些定义
```

## 接缝在哪里

```ts
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { Warden, ThreatFeed, isSensitiveTool, EgressGuard } from "@aimarket/warden";

const feed = new ThreatFeed({ feedPublicKey: process.env.FEED_PUBKEY, log });
await feed.load(process.env.FEED_URL);

const warden = Warden.create({ policy, threatFeed: feed, store, log });

async function connect(ref) {
  const client = new Client({ name: "my-host", version: "1.0.0" });
  await client.connect(new StdioClientTransport({ command: ref.command, args: ref.args }));

  const { tools } = await client.listTools();
  const verdict = await warden.vet(ref, tools);

  if (!verdict.allow) {
    await client.close();                       // 从来没有任何东西暴露给模型
    await audit.write({ server: ref.id, verdict, at: new Date().toISOString() });
    throw new Error(`${ref.id} 被 ${verdict.decidedBy} 阻止`);
  }

  const usable = tools.filter((t) => verdict.allowedTools.includes(t.name));
  await audit.write({ server: ref.id, verdict, at: new Date().toISOString() });
  return { client, tools: usable, verdict };
}
```

这个顺序换来三件事，而每一件都很容易因为挪动一行而失去：

1. **`vet()` 发生在模型看到任何东西之前。** 被阻止的工具定义，是一段从未进入上下文的提示词文本。在已经把工具交给
   模型之后再审查，那只是演戏。
2. **`blockedTools` 不等于阻止整台服务器。** 一台有一个被投毒工具、九个正常工具的服务器仍然可用；只丢掉裁定点名
   的那些。
3. **把裁定连同 `verdict.rulesets` 一起留档。** 没有规则集的版本与摘要，留档的扫描结果就无法与「服务器后来变了」
   区分开。

## 逐次调用的审批

裁定是关于*定义*的决定。敏感工具关乎的是*调用*：

```ts
async function callTool(name, args) {
  if (isSensitiveTool(name, policy) && !(await confirmWithUser(name, args))) {
    throw new Error(`${name} 需要审批`);
  }
  return client.callTool({ name, arguments: args });
}
```

模式是 glob，对工具全名做不区分大小写的匹配：`"*delete*"`、`"*transfer*"`、`"*key*"`。如果你想在用户批准该服务器
之前就告诉他哪些工具将需要确认，`classifyTools(tools, policy)` 会预先给出这个划分。

如果你的工具会发出网络请求，就把它们包起来：

```ts
const egress = new EgressGuard(["api.github.com", "*.internal.example.com"]);
const { allowed, reason } = egress.check(url);
if (!allowed) throw new Error(reason);   // 空白名单会阻止一切——这是设计如此
```

## 你必须提供的两处接缝

**`PinStore`**——两个方法。任何实现都行；唯一的要求是能跨重启存活，因为正是 pin 让漂移变得可被发现：

```ts
// 开发环境：内存实现。每次重启都会重新变成「首次接触」。
const pins = new Map();
const store = {
  getPin: async (id) => pins.get(id),
  putPin: async (p) => void pins.set(p.serverId, p),
};

// 生产环境：一个 JSON 文件就够了——一条 pin 只有 4 个小字段。
import { readFile, writeFile } from "node:fs/promises";
const store = {
  async getPin(id) {
    const all = JSON.parse(await readFile(PATH, "utf8").catch(() => "{}"));
    return all[id];
  },
  async putPin(p) {
    const all = JSON.parse(await readFile(PATH, "utf8").catch(() => "{}"));
    all[p.serverId] = p;
    await writeFile(PATH, JSON.stringify(all, null, 2), { mode: 0o600 });
  },
};
```

**`WardenLogger`**——`debug/info/warn/error/child`。多数宿主的 logger 在结构上已经满足它，所以通常可以原样传入；
`silentLogger()` 是文档化的默认值。生产环境请传一个真实的：所有门控决策与所有 feed 拒收都报告在那里，而没有它，
一个静默为空的威胁 feed 看起来跟一个正常工作的完全一样。

在 TypeScript 里，你可以把这份契约写成显式的，交给编译器守住：

```ts
import type { PinStore, WardenLogger } from "@aimarket/warden";
export interface MyStore extends PinStore { /* 你自己的方法 */ }
export interface MyLogger extends WardenLogger { /* … */ }
```

## 如何选择策略

```ts
const policy = {
  blockAtSeverity: "high",
  sensitiveToolPatterns: ["*delete*", "*transfer*", "*key*", "*password*"],
  allowUnknownServers: false,
  pinToolDefs: true,
};
```

| | `blockAtSeverity` | `allowUnknownServers` | `pinToolDefs` |
|---|---|---|---|
| 严格锁定 | `medium` | `false` | `true` |
| 推荐默认 | `high` | `false` | `true` |
| 探索某个目录 | `high` | `true` | `true` |
| 仅报告（审计一批机器） | `critical` | `true` | `false` |

来自实战的几点提醒：

- `blockAtSeverity: "info"` 不是「最高安全」，而是一个坏掉的部署：它会阻止 `TOOL_DEF_UNPINNED`，而每台服务器在
  首次接触时都带着它，于是什么都永远无法被批准。门控之所以把这条发现保持在 `info`，正是为了让收紧阈值时能优雅
  降级；不要在没读过[门控表](gates.zh.md)之前把它降到 `medium` 以下。
- 「仅报告」是一个真实可用的模式：保留裁定、什么都不阻止，在正式开启之前先看看你这批机器本来会拒掉什么。

## 不要把自己的工具塞进 WARDEN

WARDEN 审查的是**第三方** MCP 服务器。你自己的内置工具并不是一个不可信的发布方，把它们塞进这条链只会得到恰恰
相反的结果：你自己那个叫 `transfer_funds`、描述诚实的工具，会触发本来为了抓「陌生人宣传同样的事」而写的
`TOOL_DEF_*` 规则。把第一方工具放在另一条可信路径上——这是来自 ARGUS 的经验，在那里生态系统的第一方工具明确
绕过防火墙。

## 参考

- [ARGUS](https://github.com/alexar76/argus)——参考宿主。`src/mcp/host.ts` 就是这套集成的生产形态：连接时审查、
  按工具隔离、逐次调用审批、出网守卫。
- [MOMUS](https://github.com/alexar76/momus)——发布方一侧：`/warden/threat-feed` 上的已签名 feed，加上一个
  未经验证的可疑报告入口。
- [门控链](gates.zh.md) · [已签名的威胁情报 feed](threat-feed.zh.md)
