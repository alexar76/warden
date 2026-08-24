# La cadena de puertas

> 🌐 [English](gates.md) · [Русский](gates.ru.md) · **Español** · [Français](gates.fr.md) · [中文](gates.zh.md)

`Warden.vet(server, tools)` ejecuta una cadena ordenada y devuelve un solo veredicto. Esta página es
todo el procedimiento de decisión: qué mira cada puerta, qué puede bloquear y cómo se construye el
número final.

```
static-scan  →  threat-feed  →  origin  →  pinning
 (gratis)        (gratis tras    (gratis)   (gratis)
                  load)
```

El orden va de lo más barato y local primero. Nada en la cadena hace una petición de red: la única
descarga que WARDEN llega a hacer es `ThreatFeed.load(url)`, que llamas tú, antes de examinar nada.

## Cómo se ensambla un veredicto

Cada puerta devuelve `{ findings, score, fatal? }`. La cadena:

1. ejecuta todas las puertas en orden, acumulando hallazgos (cada puerta ve `prior`);
2. multiplica las puntuaciones de las puertas — la compuesta es un **producto**, así que una puerta
   mala arrastra al servidor hacia abajo en vez de quedar promediada por tres buenas;
3. bloquea si alguna puerta devolvió `fatal`, o si algún hallazgo no advisory alcanza
   `policy.blockAtSeverity`;
4. corta la cadena **solo** ante un `fatal` explícito. Un hallazgo bloqueante pero no fatal deja que
   las puertas restantes informen, para que el registro del *por qué* quede completo.

```ts
const SEVERITY_RANK = { info: 0, low: 1, medium: 2, high: 3, critical: 4 };
```

Si `policy.blockAtSeverity` no es una de esas cinco claves, el constructor registra un aviso y cae a
`"high"`. Una errata ahí era antes el peor fallo posible: `rank >= undefined` es `false` en toda
comparación, de modo que un umbral mal escrito desactivaba el bloqueo por completo, en silencio.

### Dos ejes: severidad y nivel

La severidad responde a *cuánta atención merece esto*. El **nivel** (tier) responde a *¿es esto un
defecto?* — y es un dato del hallazgo (`advisory: true`), no una consecuencia de la severidad.

Un hallazgo `advisory` se reporta, nunca bloquea y nunca cuesta una herramienta, con **cualquier**
`blockAtSeverity`. Una herramienta cuyo esquema acepta un `api_key` merece que se la señale y no es un
defecto; expresarlo bajando su severidad la volvía bloqueante para quien endureciera el umbral.

## static-scan

Escaneo local con regex sobre el `name`, la `description` y el `inputSchema` de cada herramienta. 25
reglas en el conjunto **v4**: 15 `block`, 10 `advise`, y 12 de ellas llevan un **guard** de contexto:
una comprobación con nombre que decide si una coincidencia es de verdad lo que la regla busca. Véase
[el estudio de campo](mcp-survey.es.md), la ejecución sobre 1 108 servidores que las produjo.

Cada regla declara sobre cuál de esas tres **superficies** se ejecuta, y 17 de las 25 incluyen el
nombre. Las tres que no lo hacen son las que se apoyan en un SUSTANTIVO
(`TOOL_DEF_SECRET_REQUEST`, `TOOL_DEF_CREDENTIAL_PARAM`, `TOOL_DEF_ENV_REFERENCE`): un nombre es un
identificador, `api_key` y `private_key` son partes ordinarias de uno, y rechazar
`sign_with_private_key` sería cometer el error de calibración de v1 en una superficie nueva. Las
reglas que se apoyan en una FRASE necesitan espacios y no pueden coincidir con `snake_case` en
absoluto, y las dos reglas de carga oculta hablan de caracteres que nunca son legítimos en un
nombre: esas se ejecutan en todas partes.

Hasta v3 el nombre no lo escaneaba **nada**, así que una frase de inyección, un carácter de ancho
cero o un blob base64 en el primer campo que lee el modelo no se reportaban en absoluto.

La puntuación de la puerta es `1 − penalización(peor severidad bloqueante)`; los avisos nunca la
afectan.

| peor severidad bloqueante | ninguna | info | low | medium | high | critical |
|---|---|---|---|---|---|---|
| puntuación | 1 | 1 | 0.9 | 0.7 | 0.4 | 0 |

| Código | Severidad | Nivel | ¿Nombre? | Qué detecta |
|---|---|---|---|---|
| `TOOL_DEF_INJECTION` | critical / high | block | ✅ | «ignore all previous instructions», «do not tell the user», etiquetas `<system>`, referencias al prompt del desarrollador |
| `TOOL_DEF_SECRET_REQUEST` | critical | block | — | `private_key`, `seed_phrase`/`mnemonic`, rutas `~/.ssh` |
| `TOOL_DEF_SECRET_HARVEST` | critical | block | ✅ | una herramienta cuyo cometido declarado es leer/volcar/revelar secretos |
| `TOOL_DEF_EXFIL` | critical / high | block | ✅ | «post to https://…», «forward it to…», «exfiltrate», fraseo de subida a un host |
| `TOOL_DEF_HIDDEN_UNICODE` | high | block | ✅ | caracteres de ancho cero y de control bidi — texto que el revisor no ve |
| `TOOL_DEF_BASE64_BLOB` | high | block | ✅ | una tirada base64 de 120+ caracteres en un nombre, una descripción o un esquema |
| `TOOL_DEF_DATA_URL` | high | block | ✅ | URLs `data:…;base64,` y `javascript:` |
| `TOOL_DEF_CREDENTIAL_PARAM` | medium / low | advise | — | esquema o descripción que pide `api_key`, `password`, `secret`, tokens bearer |
| `TOOL_DEF_ENV_REFERENCE` | medium | advise | — | `.env`, «environment variables» |
| `TOOL_DEF_IMPERATIVE` | low / info | advise | ✅ | «you must», «instead of» — fraseo con forma de prompt, que por sí solo no prueba nada |

`staticScanRuleset()` devuelve cada regla con **el fuente de su regex, sus flags y sus superficies**, para que un
tercero pueda reejecutar exactamente la misma regla, más `{ version, digest }`, donde el digest es
sha256 sobre la forma canónica RFC 8785 de la lista ordenada de reglas. La ordenación es por
comparación de unidades de código, nunca `localeCompare`: una collation dependiente del locale haría
que la misma tabla produjera un digest distinto en un host configurado de otra forma, que es justo la
divergencia que el digest existe para detectar.

## threat-feed

Compara la identidad del servidor y las definiciones de herramientas con registros `ThreatRecord` — 11
integrados más lo que haya añadido un feed firmado (ver [el contrato del feed](threat-feed.es.md)).

- Cualquier coincidencia ⇒ puntuación de la puerta **0**.
- `fatal` **solo** para un registro `critical` que coincide contra el *servidor*. Una coincidencia
  crítica en una *herramienta* no es fatal, así que el resto de la cadena sigue informando y la culpa
  queda circunscrita a esa herramienta — eso es lo que permite que un servidor casi correcto siga
  funcionando con una herramienta en cuarentena.
- `ThreatRecord.scope` elige la superficie: `server` (id/name/url/command/args), `tool`
  (name/description/inputSchema) o `any` — el valor por defecto cuando el registro lo omite.

Códigos integrados: `THREAT_TYPOSQUAT`, `THREAT_CRYPTO_DRAINER`, `THREAT_SEED_PHRASE`,
`THREAT_SSH_KEY_READ`, `THREAT_ENV_EXFIL`, `THREAT_DESTRUCTIVE_CMD`, `THREAT_FORK_BOMB`.

## origin

¿Declaró el operador este servidor, o llegó desde un catálogo remoto (`McpServerRef.catalog` está
puesto)?

| `allowUnknownServers` | hallazgo | puntuación | fatal |
|---|---|---|---|
| `false` (fail-closed) | `SERVER_UNDECLARED`, high | 0 | sí |
| `true` | `SERVER_UNDECLARED`, info | 1 | no |

Este interruptor significaba antes «todavía no tiene puntuación de reputación», algo que ningún
despliegue podía satisfacer: nunca se suministraron aristas de confianza al oráculo, así que todo
servidor volvía sin avalar y `false` los bloqueaba todos. La procedencia de catálogo es un hecho que
el host ya tiene en local, no necesita red y no puede provocar un bloqueo mutuo.

## pinning

Compara las definiciones actuales con la instantánea que aprobó el usuario. El hash es sha256 sobre la
forma canónica RFC 8785 del conjunto de definiciones — la misma canonicalización que usa la firma del
feed, no una segunda serialización.

| Situación | Código | Severidad | Puntuación | Fatal |
|---|---|---|---|---|
| Aún sin pin (primer contacto) | `TOOL_DEF_UNPINNED` | info | 0.9 | no |
| El hash difiere del pin | `TOOL_DEF_DRIFT` | high | 0 | con `pinToolDefs` |
| Las definiciones no tienen forma canónica (sin pin) | `TOOL_DEF_UNCANONICAL` | medium | 0.5 | no |
| Las definiciones no tienen forma canónica (con pin) | `TOOL_DEF_UNCANONICAL` | high | 0 | con `pinToolDefs` |

El primer contacto cuesta 0.1, no un bloqueo: un servidor limpio, declarado y sin pin puntúa
exactamente **0.9**, y `TOOL_DEF_UNPINNED` es `info` a propósito — con `blockAtSeverity: "info"`, un
primer encuentro bloqueante haría que todo servidor fuera inservible para siempre, ya que nada puede
fijarse antes de ser aprobado una vez.

`warden.approve(server, tools)` escribe el pin a través de tu `PinStore`. Es idempotente.

## Partición por herramienta

`allowedTools` / `blockedTools` reparten las herramientas anunciadas:

- una herramienta está **bloqueada** si un hallazgo no advisory la nombra (`finding.tool`) y alcanza
  el umbral;
- todas las demás quedan permitidas;
- las herramientas sensibles (`policy.sensitiveToolPatterns`) siguen *permitidas*: quedan marcadas
  para que el bucle de tu agente pueda exigir aprobación en cada llamada en tiempo de ejecución. Ver
  `classifyTools` / `isSensitiveTool`.

## Añadir una puerta

`WardenGate` son tres líneas de interfaz, y `new Warden({ gates, policy, log })` toma la cadena
directamente, así que puedes insertar la tuya sin hacer un fork:

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
                       message: `${input.server.name} no es un editor permitido` }],
          score: 0, fatal: true };
  }
}

const warden = new Warden({
  gates: [new StaticScanGate(), new ThreatGate(feed), new DenyByPublisher(), new OriginGate(), new PinningGate(store)],
  policy,
});
```

Dos reglas para una puerta propia: **nunca afirmes que un servicio remoto es inalcanzable si no
enviaste realmente una petición** (`test/no-phantom-gate.test.ts` lo impone sobre las puertas que se
envían) y devuelve una puntuación que puedas defender — una puerta que no midió nada debe devolver
`1`, no un 0.6 «neutro», o penaliza a cada servidor por una medición que nunca hizo.
