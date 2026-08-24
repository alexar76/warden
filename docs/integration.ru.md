# Руководство по интеграции

> 🌐 [English](integration.md) · **Русский** · [Español](integration.es.md) · [Français](integration.fr.md) · [中文](integration.zh.md)

WARDEN — это библиотека, а не прокси. Вы вызываете её в одной точке жизненного цикла своего MCP-хоста:
после того, как сервер сообщил, что умеет, и до того, как об этом узнала модель.

```
connect ──► listTools ──► warden.vet() ──► отдать модели allowedTools
                              │                    │
                              │                    └─► на каждый вызов: isSensitiveTool → спросить пользователя
                              └─► заблокировано: отключиться и записать вердикт
                                             подтверждено однажды: warden.approve() фиксирует определения
```

## Где находится шов

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
    await client.close();                       // модель так и не увидела ничего
    await audit.write({ server: ref.id, verdict, at: new Date().toISOString() });
    throw new Error(`${ref.id} заблокирован гейтом ${verdict.decidedBy}`);
  }

  const usable = tools.filter((t) => verdict.allowedTools.includes(t.name));
  await audit.write({ server: ref.id, verdict, at: new Date().toISOString() });
  return { client, tools: usable, verdict };
}
```

Три вещи, которые даёт именно такой порядок, и каждую легко потерять, передвинув одну строку:

1. **`vet()` до того, как модель что-либо увидела.** Заблокированное определение инструмента — это
   текст промпта, который так и не попал в контекст. Проверка после того, как вы уже передали
   инструменты модели, — это театр.
2. **`blockedTools` — не то же самое, что блокировка.** Сервер с одним отравленным инструментом и
   девятью нормальными остаётся пригодным; убирайте только то, что назвал вердикт.
3. **Записывайте вердикт вместе с `verdict.rulesets`.** Без версии и дайджеста набора правил
   сохранённый скан невозможно отличить от того, что сервер изменился позже.

## Подтверждение на каждый вызов

Вердикт — это решение об *определениях*. Чувствительные инструменты — про *вызовы*:

```ts
async function callTool(name, args) {
  if (isSensitiveTool(name, policy) && !(await confirmWithUser(name, args))) {
    throw new Error(`${name} требует подтверждения`);
  }
  return client.callTool({ name, arguments: args });
}
```

Паттерны — это globs, сопоставляемые без учёта регистра с полным именем инструмента: `"*delete*"`,
`"*transfer*"`, `"*key*"`. `classifyTools(tools, policy)` даёт разбиение заранее, если вы хотите
показать пользователю, что потребует подтверждения, ещё до того, как он одобрит сервер.

Если ваши инструменты делают исходящие запросы — оберните их:

```ts
const egress = new EgressGuard(["api.github.com", "*.internal.example.com"]);
const { allowed, reason } = egress.check(url);
if (!allowed) throw new Error(reason);   // пустой allowlist блокирует всё — так и задумано
```

## Два шва, которые вы обязаны предоставить

**`PinStore`** — два метода. Подойдёт что угодно; единственное требование — переживать перезапуск,
потому что именно pin-ы делают дрейф обнаружимым:

```ts
// Разработка: в памяти. Каждый перезапуск снова «первый контакт».
const pins = new Map();
const store = {
  getPin: async (id) => pins.get(id),
  putPin: async (p) => void pins.set(p.serverId, p),
};

// Продакшен: достаточно одного JSON-файла — pin это 4 небольших поля.
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

**`WardenLogger`** — `debug/info/warn/error/child`. Большинство хостовых логгеров уже удовлетворяют
ему структурно, так что обычно можно передать свой без изменений; `silentLogger()` — документированное
значение по умолчанию. В продакшене передавайте настоящий: там сообщаются все решения гейтов и все
отказы feed, а без этого молча пустой threat feed выглядит точно так же, как работающий.

В TypeScript контракт можно сделать явным и отдать его на контроль компилятору:

```ts
import type { PinStore, WardenLogger } from "@aimarket/warden";
export interface MyStore extends PinStore { /* ваши методы */ }
export interface MyLogger extends WardenLogger { /* … */ }
```

## Как выбрать политику

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
| Максимально закрыто | `medium` | `false` | `true` |
| Рекомендуемое по умолчанию | `high` | `false` | `true` |
| Изучаем каталог | `high` | `true` | `true` |
| Только отчёт (аудит парка) | `critical` | `true` | `false` |

Замечания из боевой эксплуатации:

- `blockAtSeverity: "info"` — это не «максимальная безопасность», а сломанное развёртывание: он
  блокирует `TOOL_DEF_UNPINNED`, который есть у каждого сервера при первом контакте, поэтому одобрить
  нельзя ничего и никогда. Гейты держат эту находку на `info` именно затем, чтобы ужесточение порога
  деградировало плавно; не опускайтесь ниже `medium`, не прочитав [таблицу гейтов](gates.ru.md).
- Режим «только отчёт» — реальный сценарий: сохраняйте вердикты, ничего не блокируйте и посмотрите,
  что ваш парк отверг бы, прежде чем включать блокировку.

## Не прогоняйте через WARDEN свои собственные инструменты

WARDEN проверяет **сторонние** MCP-серверы. Ваши собственные встроенные инструменты — не недоверенный
издатель, и прогон их через цепочку даёт ровно неправильный результат: ваш же инструмент с именем
`transfer_funds` и честным описанием сработает на правилах `TOOL_DEF_*`, написанных, чтобы ловить
незнакомца, рекламирующего то же самое. Держите первопартийные инструменты на отдельном доверенном
пути — это урок из ARGUS, где первопартийные инструменты экосистемы явно обходят файрвол.

## Ссылки

- [ARGUS](https://github.com/alexar76/argus) — референсный хост. `src/mcp/host.ts` — эта интеграция в
  продакшен-форме: проверка при подключении, изоляция по инструменту, подтверждение на каждый вызов,
  egress-guard.
- [MOMUS](https://github.com/alexar76/momus) — сторона издателя: подписанный feed по
  `/warden/threat-feed` плюс приём непроверенных подозрений.
- [Цепочка гейтов](gates.ru.md) · [Подписанный threat feed](threat-feed.ru.md)
