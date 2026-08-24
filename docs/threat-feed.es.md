# El threat feed firmado

> 🌐 [English](threat-feed.md) · [Русский](threat-feed.ru.md) · **Español** · [Français](threat-feed.fr.md) · [中文](threat-feed.zh.md)

WARDEN trae 11 registros de amenazas integrados. Son un suelo, no un catálogo: el sentido del feed es
que alguien que realmente caza servidores MCP hostiles pueda empujar lo que encuentra a cada
instalación, sin quedar en posición de *desbloquear* nada.

## El contrato en el cable

```
GET https://tu-host/threat-feed

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

| Campo | Regla |
|---|---|
| `records` | array de `ThreatRecord`; las entradas que no cuadran con el tipo se descartan, no es fatal |
| `timestamp` | epoch en **milisegundos, entero**. No es opcional — es lo que hace detectable un replay |
| `signature` | Ed25519, hex, sobre la forma canónica RFC 8785 de `{records, timestamp}` — **no** sobre el cuerpo crudo |

`ThreatRecord`:

| Campo | Significado |
|---|---|
| `pattern` | se compara sin distinguir mayúsculas; `*` es un glob, un patrón sin `*` es una prueba de subcadena |
| `severity` | de `info` a `critical`. Un `critical` que coincide contra el **servidor** es fatal para la conexión |
| `code` | código máquina estable, p. ej. `THREAT_TYPOSQUAT` |
| `reason` | frase humana que se muestra al operador |
| `source` | quién lo afirma — se arrastra hasta el hallazgo |
| `scope` | `server` \| `tool` \| `any` (por defecto). Contra qué superficie tiene sentido el patrón |

El scope importa más de lo que parece. `*token*` es un patrón razonable de *identidad de servidor* y un
patrón catastrófico de *herramienta*: la mitad de los servidores MCP honestos mencionan tokens en un
esquema.

## Qué comprueba WARDEN y qué hace al fallar

La regla para todos los fallos de abajo es la misma: **conservar el suelo integrado**. Un feed que no
se puede verificar se ignora; nunca reduce la protección que ya tenías y nunca bloquea el arranque.

| Comprobación | Qué evita |
|---|---|
| `feedPublicKey` configurada | Un feed sin firma se rechaza de plano — sin clave no hay registros remotos, aunque haya URL |
| Firma Ed25519 sobre bytes canónicos | Quien sirve la URL no puede añadir ni editar registros |
| Frescura: el `timestamp` firmado dentro de `maxAgeMs` (24 h por defecto, `DEFAULT_FEED_MAX_AGE_MS`) | Un replay de una instantánea de hace meses que borra en silencio cada registro añadido desde entonces. *Una firma dice quién escribió un documento, nunca cuándo te lo entregaron* |
| Desviación futura: no fechado más de `FEED_CLOCK_SKEW_MS` (5 min) por delante | Un timestamp muy en el futuro que mantendría «fresco» un documento rancio para siempre |
| Bytes canónicos (RFC 8785) | Que editor y verificador discrepen por el orden de claves JSON |
| Tamaño: `content-length` y cuerpo ≤ 512 000 bytes | El URL del feed usado como vector de agotamiento de memoria; también se mide el cuerpo, porque content-length puede faltar o mentir |
| Timeout de descarga de 10 s | Un feed colgado que bloquea tu arranque |

Los registros remotos **se añaden a** los integrados (`[...BUILTIN, ...remote]`). Un feed no puede
eliminar un registro integrado, y por tanto un editor comprometido no puede apagar la protección: solo
sumarle. Esa asimetría es deliberada: el canal ascendente (cualquiera reporta una sospecha) y el
descendente (el feed que puede denegar un servidor) no deben tener el mismo nivel de confianza.

## Publicar un feed que WARDEN acepte

La clave se genera una vez. WARDEN quiere la clave pública como **SPKI DER en hex** (88 caracteres hex
para Ed25519):

```js
import { generateKeyPairSync } from "node:crypto";

const { publicKey, privateKey } = generateKeyPairSync("ed25519");
const spkiHex = publicKey.export({ format: "der", type: "spki" }).toString("hex");
console.log(spkiHex); // → esto es lo que tus consumidores fijan como feedPublicKey
```

Firma la forma canónica de `{records, timestamp}` — reutiliza el canonicalizador de WARDEN para que
haya una sola implementación de los bytes, no dos:

```js
import { sign } from "node:crypto";
import { canonicalize } from "@aimarket/warden/jcs";

function document(records, privateKey) {
  const timestamp = Date.now();                       // ms enteros
  const payload = canonicalize({ records, timestamp }); // RFC 8785 fija el orden de claves
  const signature = sign(null, Buffer.from(payload, "utf8"), privateKey).toString("hex");
  return { records, timestamp, signature };
}
```

Dos cosas que muerden a los editores:

- **No caches el documento.** `timestamp` es una afirmación de frescura; una respuesta cacheada acaba
  publicando una rancia y todos los consumidores la rechazan.
- **Firma la forma canónica, no `JSON.stringify`.** Coinciden muchísimo más de lo que difieren, y eso
  es justo lo que hace tan caro encontrar la diferencia más tarde.

## Consumirlo

```ts
const feed = new ThreatFeed({
  feedPublicKey: process.env.FEED_PUBKEY,   // fijada de antemano, fuera de banda
  maxAgeMs: 6 * 60 * 60 * 1000,             // opcional; no finito o ≤0 cae a 24 h
  log: myLogger,                            // opcional, pero aquí es donde se reportan los rechazos
});
await feed.load(process.env.FEED_URL);      // sin URL → solo integrados, sin red
```

`feed.builtins` devuelve el suelo integrado si quieres mostrar qué se aplica sin ningún feed. Cada
rechazo es un `log.warn` con el motivo: sin logger, un feed vacío en silencio y un feed rechazado son
indistinguibles, así que en producción pasa un logger.

## Un editor de referencia

[MOMUS](https://github.com/alexar76/momus) publica este contrato en `/warden/threat-feed`, con un
endpoint `/warden/threat-feed/summary` que expone la clave SPKI en hex y los recuentos de registros, y
una entrada `/warden/report` para sospechas de campo sin verificar. Su script verificador
(`momus/scripts/verify_warden_channel.mjs`) comprueba un despliegue en vivo usando el canonicalizador
**de este paquete**, que es la única forma de probar que ambos lados coinciden en los bytes.
