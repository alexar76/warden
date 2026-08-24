# Guía de integración

> 🌐 [English](integration.md) · [Русский](integration.ru.md) · **Español** · [Français](integration.fr.md) · [中文](integration.zh.md)

WARDEN es una biblioteca, no un proxy. Lo llamas en un punto del ciclo de vida de tu host MCP: después
de que el servidor te diga qué sabe hacer, antes de que se le diga al modelo.

```
connect ──► listTools ──► warden.vet() ──► exponer allowedTools al modelo
                              │                    │
                              │                    └─► en cada llamada: isSensitiveTool → preguntar al usuario
                              └─► bloqueado: desconectar y registrar el veredicto
                                             aprobado una vez: warden.approve() fija las definiciones
```

## Dónde está la costura

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
    await client.close();                       // nunca se expuso nada al modelo
    await audit.write({ server: ref.id, verdict, at: new Date().toISOString() });
    throw new Error(`${ref.id} bloqueado por ${verdict.decidedBy}`);
  }

  const usable = tools.filter((t) => verdict.allowedTools.includes(t.name));
  await audit.write({ server: ref.id, verdict, at: new Date().toISOString() });
  return { client, tools: usable, verdict };
}
```

Tres cosas que compra este orden, y todas se pierden con facilidad moviendo una línea:

1. **`vet()` antes de que el modelo vea nada.** Una definición de herramienta bloqueada es texto de
   prompt que nunca entró en el contexto. Examinar después de haber pasado las herramientas al modelo
   es teatro.
2. **`blockedTools` no es lo mismo que bloquear.** Un servidor con una herramienta envenenada y nueve
   buenas sigue siendo utilizable; quita solo lo que el veredicto nombró.
3. **Registra el veredicto, incluido `verdict.rulesets`.** Sin la versión y el digest del conjunto de
   reglas, un escaneo guardado no se puede distinguir de que el servidor cambiara después.

## Aprobación por llamada

Un veredicto es una decisión sobre *definiciones*. Las herramientas sensibles van de *llamadas*:

```ts
async function callTool(name, args) {
  if (isSensitiveTool(name, policy) && !(await confirmWithUser(name, args))) {
    throw new Error(`${name} requiere aprobación`);
  }
  return client.callTool({ name, arguments: args });
}
```

Los patrones son globs, comparados sin distinguir mayúsculas contra el nombre completo de la
herramienta: `"*delete*"`, `"*transfer*"`, `"*key*"`. `classifyTools(tools, policy)` te da el reparto
por adelantado si quieres mostrar al usuario qué exigirá confirmación antes de que apruebe el servidor.

Si tus herramientas hacen peticiones salientes, envuélvelas:

```ts
const egress = new EgressGuard(["api.github.com", "*.internal.example.com"]);
const { allowed, reason } = egress.check(url);
if (!allowed) throw new Error(reason);   // una lista vacía bloquea todo, por diseño
```

## Las dos costuras que debes proporcionar

**`PinStore`** — dos métodos. Sirve cualquier cosa; el único requisito es que sobreviva a un reinicio,
porque los pins son lo que hace detectable la deriva:

```ts
// Desarrollo: en memoria. Cada reinicio vuelve a ser «primer contacto».
const pins = new Map();
const store = {
  getPin: async (id) => pins.get(id),
  putPin: async (p) => void pins.set(p.serverId, p),
};

// Producción: un único fichero JSON basta — un pin son 4 campos pequeños.
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

**`WardenLogger`** — `debug/info/warn/error/child`. La mayoría de los loggers de host ya lo satisfacen
estructuralmente, así que normalmente puedes pasar el tuyo sin cambios; `silentLogger()` es el valor
por defecto documentado. En producción pasa uno real: ahí se reportan todas las decisiones de las
puertas y todos los rechazos del feed, y sin eso un threat feed vacío en silencio se ve exactamente
igual que uno que funciona.

En TypeScript puedes hacer explícito el contrato y dejar que el compilador lo sostenga:

```ts
import type { PinStore, WardenLogger } from "@aimarket/warden";
export interface MyStore extends PinStore { /* tus propios métodos */ }
export interface MyLogger extends WardenLogger { /* … */ }
```

## Elegir una política

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
| Cerrado a fondo | `medium` | `false` | `true` |
| Predeterminado recomendado | `high` | `false` | `true` |
| Explorando un catálogo | `high` | `true` | `true` |
| Solo informe (auditar una flota) | `critical` | `true` | `false` |

Notas de haberlo tenido en producción:

- `blockAtSeverity: "info"` no es «máxima seguridad», es un despliegue roto: bloquea
  `TOOL_DEF_UNPINNED`, que todo servidor lleva en el primer contacto, así que nada puede aprobarse
  nunca. Las puertas mantienen ese hallazgo en `info` precisamente para que endurecer el umbral
  degrade con gracia; no bajes de `medium` sin leer [la tabla de puertas](gates.es.md).
- Solo informe es un modo real: guarda los veredictos, no bloquees nada y observa qué habría rechazado
  tu flota antes de encenderlo.

## No pases tus propias herramientas por WARDEN

WARDEN examina servidores MCP **de terceros**. Tus propias herramientas integradas no son un editor no
confiable, y pasarlas por la cadena produce exactamente el resultado equivocado: tu propia herramienta
llamada `transfer_funds` con una descripción honesta dispara reglas `TOOL_DEF_*` escritas para pillar a
un desconocido que anuncia lo mismo. Mantén las herramientas de primera parte en una vía separada y de
confianza — es una lección de ARGUS, donde las herramientas de primera parte del ecosistema evitan
explícitamente el cortafuegos.

## Referencias

- [ARGUS](https://github.com/alexar76/argus) — el host de referencia. `src/mcp/host.ts` es esta
  integración en forma de producción: examinar al conectar, cuarentena por herramienta, aprobación por
  llamada, guardia de salida.
- [MOMUS](https://github.com/alexar76/momus) — el lado editor: un feed firmado en
  `/warden/threat-feed` más una entrada de sospechas sin verificar.
- [La cadena de puertas](gates.es.md) · [El threat feed firmado](threat-feed.es.md)
