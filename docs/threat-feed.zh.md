# 已签名的威胁情报 feed

> 🌐 [English](threat-feed.md) · [Русский](threat-feed.ru.md) · [Español](threat-feed.es.md) · [Français](threat-feed.fr.md) · **中文**

WARDEN 自带 11 条内置威胁记录。它们是底线，不是目录：feed 的意义在于，真正在猎捕恶意 MCP 服务器的人可以把发现
推送到每一个安装点，同时又不会因此获得*解除*任何拦截的能力。

## 线上契约

```
GET https://你的主机/threat-feed

{
  "records": [
    { "pattern": "*wallet-drainer*", "severity": "critical", "code": "THREAT_CRYPTO_DRAINER",
      "reason": "Crypto-drainer keyword in server identity", "source": "your-scanner",
      "scope": "server" }
  ],
  "timestamp": 1786205907380,
  "signature": "f588d5a4…9706"
}
```

| 字段 | 规则 |
|---|---|
| `records` | `ThreatRecord` 数组；类型不符的条目会被丢弃，但不致命 |
| `timestamp` | epoch **毫秒，整数**。不可省略——正是它让重放可被检测 |
| `signature` | Ed25519（hex），对 `{records, timestamp}` 的 RFC 8785 规范化形式签名——**不是**对原始响应体 |

`ThreatRecord`：

| 字段 | 含义 |
|---|---|
| `pattern` | 不区分大小写比对；`*` 是 glob，不含 `*` 的模式按普通子串匹配 |
| `severity` | 从 `info` 到 `critical`。命中**服务器**的 `critical` 对该连接是致命的 |
| `code` | 稳定的机器码，例如 `THREAT_TYPOSQUAT` |
| `reason` | 给运营者看的人类语句 |
| `source` | 谁这么说——会一路带进发现里 |
| `scope` | `server` \| `tool` \| `any`（默认）。该模式在哪个面上才有意义 |

scope 的分量比看起来更重。`*token*` 作为*服务器身份*模式是合理的，作为*工具*模式则是灾难性的——一半正经的
MCP 服务器都会在 schema 里提到 token。

## WARDEN 检查什么，失败时怎么做

下面每一项失败的处置规则都相同：**保留内置底线**。无法验证的 feed 会被忽略；它绝不会降低你原有的防护，也绝不会
阻塞启动。

| 检查 | 它挡住了什么 |
|---|---|
| 已配置 `feedPublicKey` | 未签名的 feed 直接拒收——没有公钥就没有远端记录，即使配了 URL |
| 对规范化字节的 Ed25519 验签 | 提供该 URL 的一方无法增删改任何记录 |
| 新鲜度：被签名的 `timestamp` 落在 `maxAgeMs` 内（默认 24 小时，`DEFAULT_FEED_MAX_AGE_MS`） | 重放几个月前的快照、悄悄抹掉此后新增的每条记录。*签名说明的是谁写了这份文件，从不说明它何时交到你手上* |
| 未来偏移：不得超前 `FEED_CLOCK_SKEW_MS`（5 分钟）以上 | 一个远在未来的时间戳会让陈旧文档永远「新鲜」 |
| 规范化字节（RFC 8785） | 发布方与验证方因 JSON 键顺序而对不上 |
| 大小：`content-length` 与响应体均 ≤ 512 000 字节 | 把 feed URL 当作内存耗尽向量；响应体也要量，因为 content-length 可能缺失或说谎 |
| 10 秒下载超时 | 挂住的 feed 阻塞你的启动 |

远端记录是**追加到**内置记录之上的（`[...BUILTIN, ...remote]`）。feed 无法删除内置记录，因此即便发布方被攻陷，
也无法关掉防护——只能往上加。这种不对称是刻意的：上行通道（任何人报告一个可疑点）与下行通道（能拒绝某服务器的
feed）不应处于同一信任级别。

## 如何发布 WARDEN 会接受的 feed

密钥只需生成一次。WARDEN 要的公钥是 **hex 编码的 SPKI DER**（Ed25519 为 88 个 hex 字符）：

```js
import { generateKeyPairSync } from "node:crypto";

const { publicKey, privateKey } = generateKeyPairSync("ed25519");
const spkiHex = publicKey.export({ format: "der", type: "spki" }).toString("hex");
console.log(spkiHex); // → 这就是消费方固定为 feedPublicKey 的值
```

对 `{records, timestamp}` 的规范化形式签名——直接复用 WARDEN 自己的规范化器，让「字节」只有一份实现，而不是两份：

```js
import { sign } from "node:crypto";
import { canonicalize } from "@aimarket/warden/jcs";

function document(records, privateKey) {
  const timestamp = Date.now();                       // 整数毫秒
  const payload = canonicalize({ records, timestamp }); // 键顺序由 RFC 8785 固定
  const signature = sign(null, Buffer.from(payload, "utf8"), privateKey).toString("hex");
  return { records, timestamp, signature };
}
```

发布方最容易踩的两点：

- **不要缓存该文档。** `timestamp` 是一项新鲜度声明；被缓存的响应终将发布一份过期文档，而每个消费方都会拒收它。
- **签名规范化形式，而不是 `JSON.stringify`。** 两者相同的时候远多于不同的时候——这正是让日后排查那点差异变得
  昂贵的原因。

## 如何消费

```ts
const feed = new ThreatFeed({
  feedPublicKey: process.env.FEED_PUBKEY,   // 事先、带外固定
  maxAgeMs: 6 * 60 * 60 * 1000,             // 可选；非有限值或 ≤0 会回退到 24 小时
  log: myLogger,                            // 可选，但拒收原因就报告在这里
});
await feed.load(process.env.FEED_URL);      // 不传 URL → 只用内置记录，不联网
```

如果你想展示在完全没有 feed 的情况下究竟在执行什么，`feed.builtins` 会返回内置底线。每一次拒收都是带原因的
`log.warn`：没有 logger，「静默为空的 feed」与「被拒收的 feed」无法区分，所以生产环境请务必传入 logger。

## 一个参考发布方

[MOMUS](https://github.com/alexar76/momus) 在 `/warden/threat-feed` 发布该契约，并通过
`/warden/threat-feed/summary` 暴露 hex 形式的 SPKI 公钥与记录计数，另有 `/warden/report` 用于接收来自现场的
未经验证的可疑报告。它的校验脚本（`momus/scripts/verify_warden_channel.mjs`）使用**本包**自己的规范化器去检查
线上部署——这是证明双方对字节达成一致的唯一办法。
