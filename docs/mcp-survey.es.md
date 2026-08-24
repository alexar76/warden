# Lo que WARDEN encontró en 1 108 servidores MCP públicos — y en qué se equivocó

> 🌐 [English](mcp-survey.md) · [Русский](mcp-survey.ru.md) · **Español** · [Français](mcp-survey.fr.md) · [中文](mcp-survey.zh.md)

El 2026-08-24, horas después de publicar `@aimarket/warden` 0.3.0, lo apuntamos a todos los
servidores MCP públicos que podíamos alcanzar legítimamente: 2 787 servidores listados en el
registro oficial con un endpoint de red, de los cuales 1 108 respondieron a un `tools/list` real y
nos entregaron 17 491 definiciones de herramienta.

El titular no es sobre el ecosistema. Es sobre nosotros. WARDEN bloqueó 50 de esos 1 108 servidores,
y en **4** de los 50 pudimos sustentar una preocupación real. Los otros 46 son nuestro escáner
equivocándose, de seis maneras que podemos nombrar, reproducir y corregir.

Publicamos los fallos con la evidencia porque el perfil de falsos positivos de un escáner es la
única cifra que decide si alguien lo va a activar. Un escáner de envenenamiento de herramientas que
rechaza servidores honestos no es un escáner prudente; es un escáner que se desinstala, y el ruleset
v1 ya nos enseñó eso una vez.

## Qué se midió

| | |
|---|---|
| Paquete bajo prueba | `@aimarket/warden@0.3.0`, instalado desde el registro npm en un proyecto vacío — no el árbol de trabajo |
| Ruleset en vigor | v2, `sha256-gWC14PR4kUylkJaAGMnIYYX6tPhZTJ60cSB61UZxuWc=` (véase [el defecto de release](#el-defecto-de-release) más abajo) |
| Corpus | `registry.modelcontextprotocol.io`, 8 000 filas → 3 121 servidores únicos → 2 787 con endpoint remoto |
| Adquisición | MCP `initialize` + `tools/list` sobre streamable-http, un intento por servidor, timeout de 20 s |
| Gates ejecutados | `static-scan` y `threat-feed` (lista de denegación integrada, sin feed remoto) |
| Gates no ejecutados | `origin` y `pinning` — ambos deciden sobre el *estado del host* (¿declaró el operador este servidor?, ¿cambiaron sus definiciones desde la aprobación?); ninguno es una propiedad del servidor y en un estudio ambos devolverían la misma respuesta para los 1 108 |
| Política | `blockAtSeverity: "high"`, `allowUnknownServers: true`, `pinToolDefs: false` |

**No se ejecutó código de terceros.** Cada definición de herramienta vino de la propia respuesta del
servidor por la red. Por eso el corpus son servidores remotos y no los servidores stdio de las
distintas listas «awesome»: alcanzar esos significa descargar y ejecutar código ajeno, algo que un
estudio de seguridad no debería permitirse a la ligera.

### Alcanzabilidad — un hallazgo por sí mismo

Sólo el 41% de los endpoints remotos anunciados por el registro completó un handshake:

| Resultado | Servidores |
|---|---|
| respondieron `tools/list` | 1 149 (41,2%) |
| rechazo con 4xx (requiere autenticación, o ya no existe) | 1 215 |
| fallo de conexión / TLS | 298 |
| transporte `sse`, no intentado | 37 |
| 5xx | 34 |
| desajuste de protocolo (sin resultado `initialize` utilizable) | 21 |
| redirección / 410 / 429 | 32 |

De los 1 149 que respondieron, 1 108 anunciaron al menos una herramienta. Quien construya un cliente
contra el registro debería dimensionar sus reintentos y su manejo de autenticación para una **tasa
de fallo del 59% en el primer contacto**.

## Resultados

| | Servidores | Hallazgos |
|---|---|---|
| escaneados | 1 108 | 3 964 |
| limpios | 664 | — |
| con hallazgos pero permitidos | 394 | 3 472 advisory |
| **bloqueados** | **50** | **492 bloqueantes** |

Hallazgos bloqueantes por regla. Un servidor puede activar varias reglas, así que la columna de
servidores no suma 50:

| Código | Hallazgos | Servidores | Tras la revisión |
|---|---|---|---|
| `TOOL_DEF_SECRET_REQUEST` | 401 | 13 | 4 sustentados, 9 ciegos a la polaridad |
| `TOOL_DEF_DATA_URL` | 31 | 11 | todos falsos — `JavaScript:` y ejemplos de API de imagen |
| `TOOL_DEF_INJECTION` | 21 | 13 | todos falsos — `system prompt` como vocabulario del dominio, instrucciones de honestidad |
| `TOOL_DEF_SECRET_HARVEST` | 14 | 10 | todos falsos — colocación verbo+sustantivo, ventana de 30 caracteres |
| `THREAT_CRYPTO_DRAINER` | 9 | 4 | todos falsos — comodines sobre subcadenas |
| `TOOL_DEF_HIDDEN_UNICODE` | 5 | 1 | todos falsos — ZWNJ persa |
| `TOOL_DEF_BASE64_BLOB` | 3 | 2 | todos falsos — punteros `$ref` de JSON Schema |
| `THREAT_SEED_PHRASE` | 3 | 2 | todos falsos — comodines sobre subcadenas |
| `TOOL_DEF_EXFIL` | 3 | 3 | todos falsos — herramientas de seguridad nombrando el ataque |
| `THREAT_SSH_KEY_READ` | 2 | 1 | todos falsos — invocación `ssh -i` documentada |

Contado por servidor y no por hallazgo, porque una línea de plantilla repetida en 377 herramientas es
un defecto, no 377. Los cuatro casos sustentados caen en las dos reglas de credenciales.

## Lo que se sostuvo

Cuatro servidores anuncian herramientas por las que realmente pasa material secreto a través del
contexto del modelo. Los describimos sin nombrarlos: no están actuando mal, hacen un trabajo legítimo
de una forma que un host de agentes sí debería controlar, y un estudio no es un canal de divulgación.

- Un servidor de tesorería para mercados de predicción cuya herramienta toma `signer_private_key`,
  descrito como *«signer EOA private key, 0x…»*. Una clave de firma de billetera, pedida como
  parámetro de API. Exactamente el caso para el que existe WARDEN.
- Un servidor de pagos entre agentes que aprovisiona una billetera sandbox y *«return[s] its private
  key exactly once»* por el canal de la herramienta.
- Un servidor de identidad de agentes cuya prosa instruye al modelo a leer un `credentials.json`
  local y a escribir `private_key` como JWK en disco con `chmod 0600`.
- Un servidor de base de datos gestionada con un parámetro `pvkPassword` — *«Password that encrypts
  the private key»*. Un parámetro documentado de una gran API de nube y, aun así, una credencial en
  el esquema de una herramienta.

Son 4 de 50 bloqueados, o 4 de 1 108 escaneados. Todo lo que sigue son los otros 46.

## Lo que no se sostuvo

### 1. Ceguera a la polaridad — el mayor defecto

`TOOL_DEF_SECRET_REQUEST` busca la frase nominal `private key`. No lee la oración que la rodea. Así
que todo lo siguiente quedó bloqueado en `critical`, que es fatal — el servidor entero, todas sus
herramientas:

> Never send a private key: none is needed and the request is refused if one is present.
> — un generador de registros DANE/TLSA

> Use this to import your own public key so you can SSH into instances. **The private key never
> leaves your machine.**
> — un gestor de instancias en la nube

> YOU sign and broadcast the returned transaction yourself, with your own wallet's private key, on
> your own infrastructure — **Otto never sees or holds your key**.
> — un servidor de cotizaciones de swap

> …does NOT confirm the certificate matches any private key.
> — un inspector de certificados

> Use exact field names from this schema; **do not guess aliases or include private key material.**
> — un servidor SAP, en la plantilla de esquema de **sus 377 herramientas**

Ese último es toda la forma del problema en una línea: un servidor que le dice al modelo que *no*
envíe claves privadas se puntúa igual que uno que las pide y, como la regla es `critical` y por tanto
fatal, una coincidencia nominal en una plantilla compartida llevó a un servidor de 377 herramientas a
puntuación 0,00. 390 de nuestros 492 hallazgos bloqueantes son ese único sustantivo.

`TOOL_DEF_SECRET_HARVEST` — un verbo de `read|extract|retrieve|fetch|obtain|dump|reveal|collect|…`
a menos de 30 caracteres de un sustantivo de credencial — falla igual:

> Anyone holding the URL can read it, so **never store secrets**, credentials or personal data
> — un servidor de almacenamiento temporal

> Public read-only: **never collect card data, secrets or email**
> — un servidor de reservas

> it does **not** reveal or mint a standalone agent credential
> — un servidor de registro de agentes

Tres servidores bloqueados por prometer, por escrito, no hacer aquello que la regla busca.

### 2. Ceguera al rol — los escáneres quedan bloqueados

Una definición de herramienta que *describe* un ataque se puntúa como si lo *ejecutara*. Cinco
servidores, todos herramientas defensivas:

> …for prompt-injection and social-engineering (`'ignore previous instructions'`, `'send funds to'`,
> `'approve this'`, `'admin override'`, `'claim your airdrop'`…)
> — un verificador de instrucciones, bloqueado por `ignore previous`

> hidden directives that hijack agents — instruction overrides, `'don't tell the user'`, data
> exfiltration, secret harvesting, tool-shadowing, and invisible-unicode / homoglyph steganography
> — un escáner de endpoints MCP, bloqueado por `exfiltration`

> `"enum": ["exfiltration", "recon_then_destroy", "injection_then_action"]`
> — un constructor de políticas, bloqueado por los valores de su propio enum

> Detect likely leaked API keys, tokens, private-key headers, JWTs…
> — un escáner de secretos, bloqueado por `private-key`

Un atacante escribe una herramienta envenenada sin nombrar el ataque. Un defensor lo nombra en cada
frase. Nuestras reglas seleccionan al defensor.

### 3. «do not tell the user» es una instrucción de honestidad

La regla `TOOL_DEF_INJECTION` trata `do not tell the user` como ocultación. En todos los casos reales
que encontramos — cuatro servidores, cuatro de cuatro — es lo contrario: el servidor impide que el
modelo le diga al usuario algo *falso*.

> some convert in real time during the session, others batch once or twice daily, so **do NOT tell
> the user** a payment is "held until the next session"

> AFTER payment succeeds, no refund is issued automatically — the result says so explicitly; **do
> not tell the user** a refund is coming

> a `facturx-en16931` result is the payload and not a Factur-X document — **do not tell the user
> otherwise**

> **Do not tell the user** to drag assets into chat

La premisa de la regla está invertida en datos reales. Los autores concienzudos usan la frase para
suprimir tranquilizaciones alucinadas, que es exactamente el comportamiento que quiere un host de
agentes.

### 4. Colisiones de vocabulario

- **`system prompt`** → `TOOL_DEF_INJECTION`, 15 hallazgos en 6 servidores. Todos son proxies de LLM,
  gestores de personas o herramientas de configuración de agentes cuyo propósito íntegro es fijar un
  system prompt, y que declaran un parámetro `system` en su esquema. La palabra es el dominio, no el
  ataque.
- **`\bjavascript:`** con el flag `i` → `TOOL_DEF_DATA_URL`, high. Coincide con la palabra
  *JavaScript* seguida de dos puntos, que es como se escribe cualquier lista de lenguajes del mundo:
  *«TypeScript/JavaScript: `*.spec/test.{ts,js}`»*, *«plain async JavaScript: …»*,
  *«javascript: Enable JavaScript execution»*. También salta en servidores que anuncian que eliminan
  el esquema: *«the sanitizer strips … `javascript:` and `data:text/html` URIs»*.
- **`data:…;base64,`** → la misma regla, en APIs de imagen cuyo ejemplo de esquema es literalmente
  `"<url> OR data:image/png;base64,..."`, y en un scraper que dice que *filtra* los esquemas `data:`.
- **la ventana de 30 caracteres** de `SECRET_HARVEST` salta límites de oración y de JSON:
  `read an open or sealed run (pass api_key` es una coincidencia que va de la prosa al nombre de un
  parámetro.

### 5. Ceguera a la codificación — WARDEN marca un sistema de escritura

`TOOL_DEF_HIDDEN_UNICODE` informa de «zero-width or bidi control characters hiding text from review».
Un servidor lo activó cinco veces. Es un servidor iraní de cálculos legales, y el carácter es
**U+200C ZERO WIDTH NON-JOINER**, un carácter ortográfico *obligatorio* en persa:

- `بخشنامه‌ها` (circulares)
- `سهم‌الارث` (cuota hereditaria)
- `حق‌الثبت` (tasa de registro)
- `حق‌التحریر` (arancel notarial)

Nada está oculto. Así se escribe el idioma. Tal como está, la regla penaliza a los servidores en
persa, árabe e índicos por su ortografía — un control de seguridad que se lee como una política
lingüística, y eso es peor que un falso positivo.

`TOOL_DEF_BASE64_BLOB` tiene el error espejo: `/` está en el alfabeto base64, así que un puntero de
JSON Schema profundamente anidado — `#/properties/flow/items/anyOf/2/properties/outcomes/items` — se
reporta como «a long base64-encoded blob — possible hidden payload».

### 6. Los comodines del threat-feed coinciden con subcadenas

La lista de denegación integrada usa comodines `*a*b*` contra la definición concatenada de la
herramienta, sin límites de palabra ni proximidad:

- `*sweep*funds*` coincidió con una herramienta de barrido de suelo de ENS: *«Floor-sweep: buy the
  CHEAPEST N listed ENS names»* … *«and **refunds** the excess»*. El patrón encontró `funds` dentro
  de **refunds**.
- `*drain*wallet*` coincidió con un escáner anti-drainer: *«Find risky allowances that could
  **drain** your tokens»* … *«a **wallet** granted»*. La herramienta existe para detener drainers.
- `*seed*phrase*` coincidió con una herramienta de keywords de YouTube: *«For a **seed** topic,
  returns suggested search **phrases**»*.

Los tres se reportan como `critical` con el mensaje *«Crypto-drainer keyword in server identity»* —
que además se equivoca sobre *dónde* coincidió: fue en la definición de la herramienta, no en la
identidad del servidor.

## Lo que funcionó exactamente como se diseñó

La única parte del ruleset que sobrevive intacta al contacto es la **estratificación**. Los hallazgos
`advisory` se dispararon 3 472 veces — `TOOL_DEF_CREDENTIAL_PARAM` 2 016, `TOOL_DEF_IMPERATIVE`
1 437, `TOOL_DEF_ENV_REFERENCE` 19 — y no bloquearon nada, no costaron puntuación y no aislaron
ninguna herramienta. Bajo el ruleset v1, donde `api_key` en un esquema bloqueaba, esos 2 016 aciertos
habrían rechazado a buena parte del ecosistema honesto. La lección v1→v2 se sostiene con datos
reales; el trabajo pendiente está en las reglas del nivel bloqueante.

## El defecto de release

El paquete con el que escaneamos reporta ruleset **v2**, digest `sha256-gWC14PR4…`. El README **dentro
de ese mismo tarball** documenta el ruleset **v3** e imprime el digest `sha256-pah/sT4I…`. Ambas son
afirmaciones verdaderas sobre código distinto:

| | |
|---|---|
| `0.3.0` publicado en npm | 2026-08-24 08:34:08 UTC |
| commit que extrajo el paquete | 2026-08-24 08:35:12 UTC — 64 segundos después |
| commit que introdujo el ruleset v3 | 2026-08-24 09:26:50 UTC — 52 minutos tras la publicación |

Así que el artefacto que instala un desconocido no tiene ninguna regla sobre la superficie `name`,
donde v3 lleva 17 de sus 24 reglas; un carácter de ancho cero o un blob base64 en el *nombre* de una
herramienta le resulta invisible.

Después medimos cuánto cuesta eso. Repetimos el corpus idéntico contra una build v3 y comparamos por
servidor, por herramienta y por código:

**Cero diferencia.** 444 servidores con hallazgos, 50 bloqueados, 3 964 hallazgos — idéntico con
ambos rulesets. Ninguno de los 1 108 servidores reales pone en el nombre de una herramienta algo que
v3 detecte y v2 pase por alto. La publicación desactualizada es un defecto de proceso real — la comprobación en CI es el punto 9 más
abajo — y en este corpus su impacto de comportamiento es nulo, y preferimos decirlo antes que
insinuar una gravedad que no medimos.

## Qué cambia por esto

Ordenado por cuántos de los 46 corrige cada punto:

1. **Polaridad.** Un sustantivo de credencial precedido por una marca de negación (`never`, `not`,
   `no`, `does not`, `without`, `refused`) dentro de la misma cláusula no es una petición. Hasta que
   eso esté implementado, las coincidencias sólo nominales no deben ser `critical`, porque `critical`
   es fatal y un sustantivo en una plantilla compartida nunca debería tumbar 377 herramientas.
2. **Texto citado y enumerado.** Una frase dentro de un literal de cadena, un `enum` de JSON o una
   taxonomía separada por comas es una *mención*. Las menciones no bloquean.
3. **`do not tell the user`** → degradar a `advisory` a la espera de una regla que exija un objeto de
   ocultación (la herramienta, la transferencia, el archivo) y no la frase suelta.
4. **`\bjavascript:`** → hacerla sensible a mayúsculas y exigir contexto de URI; `JavaScript:` como
   etiqueta no es un esquema.
5. **U+200C / U+200D** → exentos cuando son adyacentes a escritura árabe, persa o índica. Seguir
   marcando U+200B, U+FEFF y los overrides bidi.
6. **Detección de base64** → excluir punteros JSON y rutas; exigir relleno o un umbral de entropía, no
   sólo el alfabeto.
7. **Comodines del threat-feed** → semántica de límites de palabra y una cota de proximidad, para que
   `*sweep*funds*` no pueda coincidir con `refunds`.
8. **Mensajes de hallazgo** → llevar el fragmento coincidente saneado. Los nuestros truncan el patrón
   a `signature (\b(?:read|extract|…)`, así que quien revisa no puede saber qué alternativa se activó
   sin mirar el código fuente. En este mismo estudio nos costó horas.
9. **Digest del ruleset en CI** → un release debe fallar si el `dist` publicado reporta una versión de
   ruleset distinta de la del código del que se construyó.

## Limitaciones

- **Un solo transporte.** Sólo streamable-http; se omitieron 37 servidores `sse`, y todos los
  servidores stdio del ecosistema quedan fuera por la regla de no ejecutar código. Los servidores
  stdio son la mayoría de lo que la gente realmente ejecuta en local.
- **Un solo instante.** Un `tools/list` por servidor el 2026-08-24. Las definiciones cambian, y un
  servidor honesto en el momento de la consulta puede rotar una descripción después — para eso existe
  el gate `pinning`, y pinning es precisamente lo que este estudio no pudo ejercitar.
- **«Falso positivo» es nuestro juicio.** Leímos la definición y decidimos que la marca era errónea.
  No auditamos los servidores, y un falso positivo en la *definición* no certifica la
  *implementación*: una herramienta de prosa impecable todavía puede exfiltrar al invocarse. El
  análisis estático de definiciones no ve eso, por construcción.
- **Sin verdad de referencia.** Nada del corpus está etiquetado. Podemos informar de que 46 de 50
  bloqueos fueron erróneos; no podemos informar de cuántos servidores envenenados pasamos de largo.
  Los falsos negativos son invisibles a este método, y una precisión de 4/50 no dice nada sobre la
  cobertura.
- **Faltan los servidores con autenticación.** 1 215 servidores rechazaron sin credenciales. Son
  desproporcionadamente los comerciales, así que el corpus se inclina hacia los abiertos y
  aficionados.

## Reprodúcelo

Nada de esto necesita nuestra infraestructura ni una clave. Los scripts están en
[`scripts/mcp-survey/`](../scripts/mcp-survey/) y el agregado en
[`data/mcp-survey-2026-08-24.json`](data/mcp-survey-2026-08-24.json).

```bash
cd scripts/mcp-survey
python3 harvest_registry.py          # registro -> registry_remotes.json
python3 harvest_tools.py             # tools/list en vivo -> tools_raw.jsonl
npm install @aimarket/warden@0.3.0
node scan.mjs tools_raw.jsonl scan.json
python3 classify.py                  # fragmento exacto por hallazgo bloqueante
```

`harvest_tools.py` hace dos o tres peticiones por servidor y no ejecuta nada. Si lo repites, tus
números de alcanzabilidad diferirán de los nuestros — los endpoints aparecen y desaparecen por horas.

## Línea base

Para que la próxima lectura de estas cifras signifique algo. El 2026-08-24, día del estudio y día en
que se publicó 0.3.0:

| | |
|---|---|
| versión en npm | 0.3.0, publicada a las 08:34 UTC |
| descargas de 0.3.0 en npm | ninguna registrada — los contadores del registro llegan hasta 2026-08-23, así que aún no existen datos |
| descargas en npm, semana anterior | 1, del marcador de nombre `0.0.1` |
| estrellas en GitHub | 0 |

Sean lo que sean estos números la próxima vez que se actualice esta página, aquí es donde empezaron.
