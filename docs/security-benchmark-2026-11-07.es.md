# Evaluación de seguridad MCP: WARDEN — 2026-11-07

**Estado: comparación de cinco productos publicados completa en ambos hosts.** Cada producto intentó las 18.110 filas. Cobertura completa, errores y paridad se informan aparte; cohortes mixtas no son exactitud global. El posterior candidato runtime `.2` tiene su estado separado abajo.

[English](security-benchmark-2026-11-07.md) · [Русский](security-benchmark-2026-11-07.ru.md) · [Español](security-benchmark-2026-11-07.es.md) · [Français](security-benchmark-2026-11-07.fr.md) · [中文](security-benchmark-2026-11-07.zh.md)

El autor mantiene WARDEN y HISTOR, con asistencia de IA. Es una comparación del mantenedor, no una certificación independiente. Las mediciones comparativas publicadas aquí son remotas, en gVisor. Un piloto local anterior queda excluido y sus artefactos `dist`/Vitest/Vite fueron eliminados; no se afirma que nunca hubiera existido un piloto local.

Los enlaces de evidencia descargan el ZIP público del informe. El título de cada enlace indica el archivo correspondiente dentro del ZIP.

## Qué se compara y con qué versiones

Se mide la respuesta del escáner a las definiciones de herramientas anunciadas por MCP. Analizar una descripción no equivale a ejecutar la herramienta, observar que un modelo siga una inyección ni medir el éxito de un ataque contra un modelo.

| Implementación | Paquete / entrada | Identidad de la ejecución nueva |
|---|---|---|
| WARDEN, producto publicado principal | `@aimarket/warden` | npm `0.23.0`, ruleset `17`, 40 reglas; digest `sha256-UOfK25xo6D8vrKEVfNFBTBVn5OspyaZut9vC9Z9Q5JE=` |
| mcp-audit | PyPI `mcp-audit-scanner[mcp]` | `0.28.0` |
| mcp-shield | npm `mcp-shield` | `1.0.4` |
| truecopy | npm `@askalf/truecopy` | `0.10.5` |
| mcpsentry | npm `@roshan6335/mcpsentry` | `0.1.5` |

WARDEN principal usa el tarball npm publicado verificado, SHA-256 `833841f2aab89df4c51b5f84385ad69c8ffd7dcf5a7725ec0eb4ebabe594b7ee`. El anterior build congelado «v17» contiene seis archivos dist modificados para wrapper/filtrado de resultados: no es idéntico byte a byte a npm 0.23.0 ni reemplaza su columna. El candidato no publicado y posterior al análisis de fallos es `0.23.1-dev.20261107.1`, ruleset `19`, 43 reglas, 32 bloqueantes, digest `sha256-XfRh1+VZoAM6PGtbmqprnSX/eF16qNYOk0o+ilRFxXw=`. El primer v18 conserva su digest `sha256-aXkZQj8F1fKgcTpyrfNdgQSQMuzdc1yabcKiGPVKjMo=`. No se publicó en npm. Los resultados y versiones de octubre siguen en [la comparación histórica](scanner-comparison.es.md).

Los paquetes publicados y corpus públicos originales son obtenibles. Repetir exactamente los fixtures y adaptadores del mantenedor requiere publicar sus fuentes. Los metadatos permiten inspeccionar id, umbrales, cobertura y hashes de salida, pero no permiten por sí solos una reproducción independiente completa. El código candidato19 tampoco está publicado: hashes y recibos son auditables, no un build reproducible externamente. El paquete público contiene informes, metadatos e imágenes, no fuentes del producto/banco privado.

## Implementaciones reales frente a replay

La comparación masiva usa las API nativas completas de análisis/clasificación de las implementaciones reales, con estado nuevo. No afirma que las 18.110 filas pasaran por stdio MCP en cada producto. La paridad CLI/MCP y la interoperabilidad viva se comprueban por separado.

| Categoría | Inventario explícito | Alcance | Estado |
|---|---|---|---|
| Paquetes stdio reales, candidato19 | `@modelcontextprotocol/server-filesystem@2.2.0` (16 herramientas), `@modelcontextprotocol/server-memory@2.1.0` (9), `@modelcontextprotocol/server-sequential-thinking@2.1.1` (1), WARDEN (9) | SDK oficial Node MCP `1.32.1`; directo y envuelto: descubrimiento, llamada sintética segura, rechazo de herramienta desconocida y ping posterior | Ambos hosts: 8/8 sesiones y 4/4 pares de digest de listas iguales |
| HTTP público, candidato19 | DeepWiki (3), Microsoft Learn (3), Cloudflare Docs (2) | Solo `initialize` y `tools/list` | Ambos hosts: 3/3 sin errores, todos permitidos |
| Definiciones congeladas | 3.177 vistas fijas y 14.933 filas HISTOR | API nativas completas, sin ejecutar código del servidor original | Completo en ambos hosts |
| Paridad representativa CLI/MCP | Node: 10/10 cada uno; mcp-audit Python: 13 acuerdos nativos/API con seis analizadores, incluido un resultado parcial; WARDEN publicado: 20/20, lista de 1,17 MB y ataque/limpio/repetición | Entrada nativa frente al adaptador | Un acuerdo parcial no es un veredicto completo |

Véase [evidencia viva](https://modelmarket.dev/blog/media/warden-security-comparison-2026-11-07/reports-and-data.zip "Archive member: evidence/live/README.md"). El recibo SDK final corresponde a `sdk19-final` remoto; las copias locales `sdk19` conservan el primer pase. Las llamadas sintéticas no usan archivos del usuario ni credenciales de producción. HTTP: `https://mcp.deepwiki.com/mcp`, `https://learn.microsoft.com/api/mcp`, `https://docs.mcp.cloudflare.com/mcp`. Son versiones observadas, no una afirmación de últimas versiones.

## Inventario exacto de fixtures

**23 ataques del mantenedor**, definidos en [`build_sets.py`](../scripts/scanner-comparison/build_sets.py):

`A01-important-tag`, `A02-ssh-into-param`, `A03-shadowing-bcc`, `A04-zero-width-hidden`, `A05-unicode-tags`, `A06-base64-payload`, `A07-russian`, `A08-chinese`, `A09-paraphrase`, `A10-schema-hidden`, `A11-annotation-injection`, `A12-exfil-url`, `A13-name-injection`, `A14-private-key-param`, `A15-seed-phrase`, `A16-javascript-url`, `A17-ignore-previous`, `A18-system-tag`, `A19-call-first-history`, `A20-env-dump`, `A21-destructive`, `A22-concealment`, `A23-spanish`.

**12 controles benignos:**

`B01-never-send-key`, `B02-injection-scanner`, `B03-api-key-param`, `B04-javascript-word`, `B05-persian-zwnj`, `B06-refunds`, `B07-send-email`, `B08-secret-scanner`, `B09-password-vault`, `B10-upload-drive`, `B11-ssh-howto`, `B12-translate`.

**Fixtures de terceros: 10 ataques, uno benigno y uno ambiguo.**

| Fuente | Casos y etiquetas |
|---|---|
| mcp-audit, commit `fdc8762eb2d5abb708bdaf767ec5a8140b2ab9a2` | Ataques: `behavioral_override_stealth`, `cloud_credential_exfiltration`, `crowdstrike_add_numbers`, `fake_postmark_exfiltration`, `invariant_labs_ssh_exfiltration`, `xml_injection_override` |
| mcp-shield, commit `379140c3555bf35c6f8f451ee320da24302e792e` | Ataques: `calculateSum`, `sendEmail`, `readFile`, `getFactOfTheDay`; benigno: `whatsapp`; ambiguo: `fetchWeather` |

El caso ambiguo se informa por separado y se excluye de los denominadores de detección y errores benignos. El origen externo no convierte un fixture conocido en una prueba ciega nueva: estos datos estuvieron disponibles durante el desarrollo de WARDEN.

## MCPTox: unidades y los 45 nombres

La extracción archivada contiene **485 definiciones envenenadas distintas**: 267 en 22 servidores dev y 218 en 23 servidores test. Hay además 225 definiciones con representación de prompt modificada y 45 listas de servidores limpios. Son unidades diferentes, no una única cantidad de «servidores».

Los **1.348 escenarios** son otra vista solapada de las 485 definiciones. La auditoría remota del commit oficial `f85189f9ad12504c197c7f920ab818a40657b1fa` retuvo 1.338 valores server/frame únicos y 10 instancias duplicadas conservadas, cero descartadas; 702 con saltos literales y 646 con normalización de saltos escapados. Los hashes JSON coinciden con el archivo. El repositorio no declara licencia: se publican metadatos factuales, no definiciones, esquemas, payloads o código Python originales. Los 45 controles limpios contienen 362 herramientas, frente a las 353 del artículo; la deduplicación no resuelve esa diferencia. Véanse [extracción](../scripts/scanner-comparison/build_mcptox.py) y [split](../scripts/scanner-comparison/results/2026-10-09-mcptox.json).

La proyección full-frame conserva literalmente el texto de argumentos, pero declara como strings las propiedades extraídas de parámetros. No reconstruye los tipos nativos originales; sus resultados corresponden a esa proyección, no a una ejecución exacta de los esquemas originales.

**Dev — 22:** AWSKnowledgeBase; AdFin; AlphaVantage; BaiduMap; ClickHouse; Codacy; Commander; DoDo Payments; Email; EverArt; Everything; Fetch; Flomo; Google Maps; Memory; Prisma; SQLite; Sentry; Slack; Tavily; gNucleus Text to CAD; mcp-simple-arxiv.

**Test — 23:** 12306-mcp; AgentQL; AmapMap; Apify; BraveSearch; Claude Post; DumplingAI; E2B; FileSystem; Financial Dataset; Git; Github; Gitlab; GoogleDrive; Gyazo; HyperBrowser; KeywordsPeopleUse; OP.GG; Puppeteer; QuickChart; Redis; Sequential Thinking; wechat.

Son nombres del dataset, no afirmaciones de disponibilidad o afiliación actuales. El split se fijó ordenando por `sha256("mcptox split 2026-10-09|" + server_name)`: primeros 22 dev, restantes 23 test. Las listas anteriores conservan el orden del archivo de resultados.

| Entrada archivada | SHA-256 de los bytes originales |
|---|---|
| `pure_tool.json` | `54b1eb0e9d7b2f18465266aa9d9dfda828cd558b1269b74731ec2c5d8579e617` |
| `response_all.json` | `79a90049be931c59e71446d6180b1d7f0d196d123d08a59bc155d142b5041c03` |

Estos hashes históricos no sustituyen el manifest nuevo de fuentes, archivos `def_tool`, JSON y configuraciones generadas. El parser trata Python como datos y no lo ejecuta. «Served» reproduce la definición extraída del servidor; «decorated» mide por separado prefijos como `<IMPORTANT>` o «Ignore the previous instructions».

## Archivo público y observaciones de paquetes

La cohorte principal son **986 listas archivadas** del [corpus 2026-10-01](data/mcp-corpus-2026-10-01.jsonl.gz). [August carryover](data/mcp-corpus-2026-10-01-august-carryover.jsonl.gz) añade **41 observaciones**, con **28 coincidencias exactas nombre+definición**: **999 instantáneas únicas nombre+definición**. No son 1.027 servidores independientes.

El [inventario completo](https://modelmarket.dev/blog/media/warden-security-comparison-2026-11-07/reports-and-data.zip "Archive member: INVENTORY-README.md") enumera **las 18.110 filas**, nombres, versiones registradas, etiquetas, herramientas, digest y procedencia. Descargas: [CSV.gz](https://modelmarket.dev/blog/media/warden-security-comparison-2026-11-07/reports-and-data.zip "Archive member: public-inventory.csv.gz"), [JSON.gz](https://modelmarket.dev/blog/media/warden-security-comparison-2026-11-07/reports-and-data.zip "Archive member: public-inventory.json.gz"), [manifest](https://modelmarket.dev/blog/media/warden-security-comparison-2026-11-07/reports-and-data.zip "Archive member: public-inventory-manifest.json"). Solo metadatos, sin contenido de ataque no licenciado.

Están disponibles **14.933 filas de versiones HISTOR: 12.023 npm y 2.910 PyPI**, 14.449 toolsets distintos y 272.657 registros de herramientas, sin descartes ni diferencias de cuenta. La recomputación MTL y hashes de archivos se verificaron en ambos hosts. Del [archivo 2026-10-20](https://histor.modelmarket.dev/datasets/2026-10-20/toolsets.jsonl.gz) se recuperaron 14.930 filas; otras tres, mediante URL API públicas inmutables. El [manifest](https://histor.modelmarket.dev/datasets/2026-10-20/manifest.json) y tree-head firmados Ed25519 se verificaron contra `did:key` fijado. El archivo es CC-BY-4.0, atribuido a Aleksandr Artamokhov / HISTOR, *HISTOR: MCP tool definitions and how they change*, snapshot 2026-10-20. Las tres respuestas API no declaran licencia propia y su publicación es solo de metadatos.

Se usan los campos base MTL históricos exactos, sin mezclar title, annotations o extensiones actuales. Una observación no es una instalación/ejecución nueva. Datos sin etiqueta miden frecuencia de señales al umbral; afirmar falsos positivos requiere etiquetas o revisar el texto pertinente.

| Entrada / prueba | SHA-256 |
|---|---|
| Catálogo 3.177 vistas | `e29baa05fbdbf46e34631ff2c75f0b4f535f0188054dd4499699bd189a3dc757` |
| Catálogo 14.933 paquetes | `78d4dab7125318b80cc35302e7cf1cfc1a49fa6f310957ed7b8fddfb538375b6` |
| Prueba de recuperación HISTOR | `8cdb0faf62c72f947baf30f74d6523fc6fd5b68720b44f4b765a0f804489cf7e` |
| Resultados grouped finales | `44732cdfa369f0f912491212d1910883a6071c4ce4727cfc30911adb828d7a3b` |
| Prueba final por caso entre hosts | `a0773f6622290268129cc48323dab0b1b84dc5652d1b2b1ba20e679c63a01205` |
| Manifest SHA-256 final | `17d6e7ebd85dede970d77f319bf3734478a037bf9fd971a53f5bbd07b4fce3f8` |

Los catálogos usan `warden.shared-lazy-inputs/v1`. `toolsFileSha256` calcula bytes UTF-8 exactos; `toolsSha256`, JSON Python 3.13 compacto con claves ordenadas, Unicode y orden de arrays conservados, valores no finitos rechazados; no se afirma JCS. Wire id: `c` y los primeros 32 hex de SHA-256 de `warden shared inputs 2026-11-07|` + clave, igual entre productos, versiones y hosts.

## Protocolo remoto registrado

1. Fijar código, digest de reglas, versiones, hora de consulta de registros, hashes de integridad publicados, dependencias y digest de imagen antes de interpretar resultados. Conservar comandos y salidas originales.
2. Registrar SHA-256 de cada entrada: descarga, definición extraída, JSON de replay, etiquetas, split, config y banco. Conservar id estables, versiones de transformación y procedencia.
3. Pases masivos: `runsc`, sin red, UID/GID 501:501, root/source/runtime/data solo lectura, cap-drop ALL, no-new-privileges, tmpfs y resultados separados. Imagen `sha256:db7085498187e8477fa462d5f1652d62bdf4b8af29ea3666bd1748a8315631a5`, Node 24.22.2/Python 3.13.18. Node: 1 CPU/768 MiB, recibo pids128. Audit base: 1 CPU/768 MiB; HISTOR: attested 1 CPU/768 MiB/un worker, PingBlip 2 CPU/1536 MiB/dos workers, pids256. `cpu.max`/`memory.max` verificados. Audit HISTOR UTC 2026-11-07: attested 20:33:21–21:13:27, PingBlip 20:33:15–21:34:48; no es comparación controlada de velocidad. Stdio/HTTP vivos tienen ajustes separados UID1000, 0,5 CPU/512 MiB y bridge/256 MiB.
4. Usar la API nativa completa de análisis/clasificación con estado nuevo por objetivo. mcp-audit ejecuta sus seis analizadores predeterminados. Verificar adaptadores mediante los casos CLI/MCP separados. WARDEN: `allowUnknownServers: true`, `sensitiveToolPatterns: []`. Rechazos cold-lock/unpinned de truecopy separados de la clasificación de contenido.
5. Guardar intentos iniciales y reintentos por separado; declarar timeout y política de reintento antes. Error, omisión y rechazo del protocolo no son allow. Nunca rellenar resultados nuevos con veredictos antiguos.
6. Se conservan salidas nativas, normalización, errores y hashes. La prueba final compara clave, wire id, SHA-256 exacto de entrada, versión/código/imagen, estado, HC/any/advisory y SHA del objeto nativo completo. Solo se normalizan `finding_path` temporal propio de mcp-audit y evidencia state-file de `RUGPULL-000`; texto/códigos/severidades conservados.

[Descargar ZIP de informes y datos](https://modelmarket.dev/blog/media/warden-security-comparison-2026-11-07/reports-and-data.zip): cinco idiomas offline, `grouped-results-v2.json`, `figure-cross-host.json`, métodos y metadatos por caso. Las filas públicas contienen estados, señales y hashes; no se prometen hallazgos nativos completos ni payloads sin licencia como descargas públicas.

mcp-audit invoca nativo `run_scan_async(extra_paths=[fresh_config], connect=True, guardrail_drift=True)`. Solo se sustituye transporte `connect_and_enumerate`: objetos capturados validados por SDK `ListToolsResult` y convertidos con `_tool_info` nativo. Analizadores, toxic-flow, delegación, annotations y scoring siguen activos; HOME/cwd/config/rug-pull nuevos. Online/API/LLM desactivados; timeout 30 s retira worker como incompleto. WARDEN: `blockAtSeverity=high`, `allowUnknownServers=true`, `sensitiveToolPatterns=[]`, `pinToolDefs=true`.

## Umbrales y denominadores

Umbrales: WARDEN `allow: false` nativo static-scan/threat-feed; mcp-audit `HIGH` / `CRITICAL` de definición del pipeline completo; mcp-shield `HIGH Risk`; truecopy señales nativas HIGH/CRITICAL; mcpsentry `HIGH` / `CRITICAL`. Cualquier señal truecopy, incluso advisory, puede ser poisoned/retenida por proxy; HC no representa toda retención y unpinned/cold-lock es política separada.

La columna común es una **señal HIGH/CRITICAL**, no una acción de bloqueo idéntica. WARDEN emite allow/block y truecopy relaciona su clasificación con la retención del proxy. mcp-shield puede salir con código 0 y hallazgos; mcpsentry sale con 1 solo para critical, mientras high-only puede salir con 0. Las señales de herramientas que solo informan no se llaman bloqueos impuestos.

Separar **positivo al umbral**, **bajo umbral/advisory-only**, **sin hallazgo**, **error/parcial**, **skipped** y **not run**. Cualquier señal incluye positivos al umbral. Ruido de rutas, configuración o baseline inicial se conserva y excluye con la misma regla para todos.

Se conserva normalization-v1: omitía tres detecciones SSH critical legítimas de WARDEN threat-feed al seleccionar solo static-scan. Normalization-v2 incluye todos los gates relevantes; raw outputs sin cambios, sin necesidad de repetir el motor. En WARDEN observado solo se excluyó info `TOOL_DEF_UNPINNED`. La misma exclusión de ruido del banco/lanzamiento/baseline aplica a todos los productos, evitando que el pinning inicial produzca un any-signal engañoso de 100%. Se informan señales HC, cualquier señal pertinente y advisory-only = any − HC.

Por escáner/cohorte: programados `N`, resultados completos `C`, positivos al umbral `B` (campo JSON), bajo umbral/advisory-only `A`, errores/parciales `E`, omitidos `S`, no ejecutados `U`; `N = C + E + S + U`, `C = B + A + no-finding`. Tasa de señales al umbral `B/C`; es recall solo dentro de cohortes etiquetadas como ataque. Cobertura `C/N`, con cuentas. Mostrar también `B/N` ante errores sin convertirlos en verdaderos negativos. Bloqueo impuesto es un resultado separado por producto; falsos positivos requieren etiquetas/revisión. Ambiguos separados.

MCPTox ataque: por definición; limpio, público y carryover: por snapshot de servidor; HISTOR: por objetivo de paquete. Una señal de herramienta al nivel elegido hace positivo al objetivo; cuentas por herramienta son diagnóstico adicional.

### Escaneos parciales y compatibilidad

Dos registros HISTOR de mcp-audit alcanzan límites nativos: 5.000 nodos de esquema/profundidad 64 y 65.536 caracteres de texto por herramienta. Son `E: parcial`, fuera de cobertura completa y de `B/A` principales, aunque exista señal parcial. Un acuerdo nativo/API parcial no es un escaneo completo.

mcp-shield rechaza 31 listas HISTOR por validación estricta del SDK MCP. Los clientes raw JSON-RPC nativos de mcpsentry y truecopy no usan ese validador. Un caso rechazado de 42 herramientas pasa CLI/API de mcpsentry sin hallazgos: compatibilidad real, no omisión del adaptador. HISTOR mcp-shield: attested `C=14.902/14.933`, 31 errores de esquema; PingBlip `C=14.901/14.933`, 31 de esquema y un timeout. Ambos: HC 5.354 / any 6.767 entre resultados completos. Frecuencia positiva sin etiquetas, no FPR; comparación final completa.

El caso separado de paridad mcp-shield de 3 MB pasó en 52,18 s al ampliar el plazo combinado nativo+API de 30 a 90 s; cada motor tardó unos 28 s. Se conserva el primer timeout. El presupuesto API por caso sigue en 30 s: no es fallo del detector ni cambio oculto del timeout masivo.

## Resultados nuevos

### Primer candidato WARDEN con regresión conservada

El primer candidato v18 perdió tres detecciones frente a v17: `FileSystem_20`, `FileSystem_22`, `FileSystem_23`. Estos fallos medidos se conservan. Una reparación posterior es otro candidato y no una evaluación sobre datos nunca vistos.

| Superficie / unidad | Build v17 congelado anterior | Primer v18 bloqueados |
|---|---|---|
| 485 definiciones servidas originales | 460/485 | 457/485 |
| Test histórico conocido, 218 definiciones | 210/218 | 207/218 |
| 225 definiciones decorated | 225/225 | 225/225 |
| 1.348 escenarios completos de prompts, con filas duplicadas | 1.331/1.348 | 1.331/1.348 |
| 45 servidores limpios, 362 herramientas | 0/45 | 0/45 |

Ambos hosts coincidieron. La ruta MCP real y la de biblioteca coincidieron en 2.103/2.103 casos por versión y host, 8.412 comparaciones en total. Es paridad de rutas/hosts, no éxito de ataques contra modelos. Recibo remoto: `/opt/warden-tests/20261107-mcptox-v18/results/final-report/REPORT.md`; el informe pareado ampliado verificado figura abajo. No implica publicación en npm.

El candidato v19 verificado aborda sobrescritura SSH pública como alteración de seguridad y lectura de `/etc/shadow` como acceso a secretos. Recupera `FileSystem_20` y `FileSystem_23`; `FileSystem_22`, requisito de lectura pública, sigue siendo secuestro no bloqueado. No se reetiqueta benigno ni se retira del denominador. Los tres fallos iniciales permanecen.

| Candidato19, vista | Bloqueos WARDEN / completos | Errores |
|---|---|---|
| Ataques propios / benignos, separados | 23/23; 0/12 | 0 |
| Ataques terceros / benigno / ambiguo, separados | 10/10; 0/1; 0/1 | 0 |
| Definiciones nativas / test histórico, separados | 459/485; 209/218 | 0 |
| Escenarios completos / decorated, separados | 1.331/1.348; 225/225 | 0 |
| Servidores limpios | 0/45 | 0 |
| Public-main / carryover, separados | 3/986; 1/41 | 0 |

Cada versión v18/v19 en cada host: MCP real/biblioteca **3.177/3.177**. Filas completas comparadas entre hosts **12.708/12.708**, siete controles de identidad verdaderos. Paridad operativa, no detección total. [Informe](https://modelmarket.dev/blog/media/warden-security-comparison-2026-11-07/reports-and-data.zip "Archive member: evidence/candidate19/REPORT.md"), SHA-256 `e699ba593242406b31f366b34d3e104dcf567094fd97421a62fbba8ded958989`; JSON pareado `30996c170fd4284991ac4624ee88cda765ae26cb2393a8bbdeefa23913847a4e`.

### Resultados finales de cinco productos publicados

WARDEN principal es npm publicado 0.23.0/rules17, no el build modificado ni candidato19. Son nuevas mediciones remotas, no cifras de octubre sustituidas.

Celdas: **HC / any / advisory-only**, advisory-only = any − HC. Todas las filas base: `C=N`, `E=S=U=0`; excepciones HISTOR abajo. HC/any coinciden entre hosts. WARDEN principal es npm publicado 0.23.0/rules17. No sumar vistas solapadas en exactitud global.

| Cohorte / unidad | WARDEN npm 0.23.0 | mcp-audit 0.28.0 | mcp-shield 1.0.4 | truecopy 0.10.5 | mcpsentry 0.1.5 |
|---|---|---|---|---|---|
| 23 ataques propios | 20 / 23 / 3 | 11 / 13 / 2 | 6 / 10 / 4 | 3 / 8 / 5 | 4 / 4 / 0 |
| 12 benignos propios | 0 / 3 / 3 | 1 / 2 / 1 | 1 / 2 / 1 | 1 / 1 / 0 | 2 / 2 / 0 |
| 10 ataques terceros | 10 / 10 / 0 | 10 / 10 / 0 | 8 / 9 / 1 | 1 / 7 / 6 | 5 / 5 / 0 |
| 1 benigno tercero | 0 / 0 / 0 | 0 / 0 / 0 | 0 / 0 / 0 | 0 / 0 / 0 | 0 / 0 / 0 |
| 1 ambiguo tercero | 0 / 0 / 0 | 0 / 0 / 0 | 0 / 1 / 1 | 0 / 0 / 0 | 0 / 0 / 0 |
| 485 definiciones nativas MCPTox | 460 / 474 / 14 | 56 / 392 / 336 | 56 / 71 / 15 | 1 / 31 / 30 | 19 / 19 / 0 |
| …267 dev | 250 / 257 / 7 | 17 / 214 / 197 | 15 / 25 / 10 | 1 / 4 / 3 | 11 / 11 / 0 |
| …218 test histórico conocido | 210 / 217 / 7 | 39 / 178 / 139 | 41 / 46 / 5 | 0 / 27 / 27 | 8 / 8 / 0 |
| 225 decorated MCPTox | 225 / 225 / 0 | 222 / 225 / 3 | 41 / 95 / 54 | 135 / 141 / 6 | 136 / 136 / 0 |
| 1.348 escenarios completos | 1331 / 1338 / 7 | 951 / 1264 / 313 | 158 / 570 / 412 | 432 / 491 / 59 | 460 / 460 / 0 |
| 45 servidores limpios MCPTox | 0 / 7 / 7 | 0 / 3 / 3 | 3 / 6 / 3 | 0 / 0 / 0 | 1 / 7 / 6 |
| 986 snapshots públicos | 4 / 388 / 384 | 43 / 159 / 116 | 343 / 451 / 108 | 2 / 39 / 37 | 86 / 450 / 364 |
| 41 observaciones carryover | 2 / 37 / 35 | 12 / 24 / 12 | 33 / 35 / 2 | 1 / 3 / 2 | 21 / 38 / 17 |
| 14.933 filas históricas de paquetes | 409 / 6327 / 5918 | 481 / 2089 / 1608 | 5354 / 6767 / 1413 | 15 / 252 / 237 | 1449 / 6362 / 4913 |

### Cobertura completa y acuerdo exacto entre hosts

Cada producto tiene `N=18.110` por host, `S=U=0`, y todas las entradas emparejadas. Cero ausencias, diferencias de identidad de entrada/motor o resultados completos diferentes. Los incompletos no entran en el denominador de acuerdo.

| Producto | C attested / PingBlip | E attested / PingBlip | Idénticos / pares completos | Errores |
|---|---|---|---|---|
| WARDEN npm | 18110 / 18110 | 0 / 0 | 18110 / 18110 | 0 |
| mcp-audit | 18108 / 18108 | 2 / 2 | 18108 / 18108 | 2 parciales en ambos |
| mcp-shield | 18079 / 18078 | 31 / 32 | 18078 / 18078 | 31 de esquema en ambos; 1 timeout solo PingBlip |
| truecopy | 18110 / 18110 | 0 / 0 | 18110 / 18110 | 0 |
| mcpsentry | 18110 / 18110 | 0 / 0 | 18110 / 18110 | 0 |

Candidato19 `.1` adicional: 18.110/18.110 pares completos; v18 HISTOR: 14.933/14.933. HISTOR candidato19: 407 HC / 6327 any / 5920 advisory-only; WARDEN publicado: 409 / 6327 / 5918. Ningún veredicto HISTOR v18→v19 cambió. Una revisión limitada de dos pasajes permitidos tras v17 identificó provisión legítima de claves públicas: `@krovacloud/mcp@0.3.16` (`create_cube`, `sshPublicKey`) y `@runpod/mcp-server@4.4.0` (`update-ssh-keys`, `keys`). Se juzgan esos pasajes, no la seguridad de todo el paquete; no se redistribuye texto original.

Author35 e independent12 son cohortes mixtas: totales positivos al umbral no son recall. Se usan etiquetas separadas 23/12 y 10/1/1. La interoperabilidad viva corresponde al candidato19 y no es una celda de la comparación de cinco productos.

## Validación de candidatos y procedencia

v18 anterior: 1.517/1.517 pruebas en 62 archivos por host, typecheck/build aprobados; red-team separado 0/28 delivered, no ASR de cinco productos. El testigo de directorio completo fue incompleto porque cambió un script vecino; producto ejecutado y 1.090 archivos source/test/script capturados estables.

Candidato19: **1.536/1.536 pruebas en 63 archivos por host**, typecheck/build/red-team salida 0, sin OOM; attested 288,085 s, PingBlip 558,354 s. Contadores README/landing obsoletos motivaron reintentos pese a 1.534 pruebas de detector ya aprobadas. Validación solo cambia contadores en cinco README, no el detector; 521 runtime/source/test idénticos byte a byte, digest `f4732e8beb77342ae250ac11126859ef59cf5e9bf3d74e8e46221b8d856d3231`. Valida el candidato congelado, no todo el workspace. Diagnósticos iniciales e intento obsoleto interrumpido de Blip conservados aparte.

## Build runtime posterior .2

`0.23.1-dev.20261107.2` es distinto del `.1` congelado: acepta MCP blob-resource válido sin `mimeType` opcional, manteniendo análisis de objetos metadata/structured similares. Ambos hosts: **1.536/1.536 pruebas en 63 archivos**, typecheck/build/red-team salida0; attested 293,705 s, PingBlip 554,284 s. Pasan 304 pruebas enfocadas a 1 CPU normal con plazos sin cambios, SDK 8/8 sesiones y 4/4 pares de listas. Se conserva el timeout inicial a 0,25 CPU, sin repetición a capacidad normal.

Pruebas independientes binary/SDK preservan un blob válido de 400k con/sin MIME. Resultados plaintext/object-blob/poisoned-metadata inválidos se retienen tras una ejecución, sesión viva; es compatibilidad de filtrado de resultados, no prevención de efectos del instrumento. Las 23 comprobaciones CLI/library `.1`/`.2` coinciden en hallazgos y scores. Los 320 archivos fuente/distribución fuera del módulo result-screen modificado son idénticos a `.1`, SHA-256 `5ff407cf78742ae18fd593065e9c9bd552bba45f3fab91f27fae9f45adb13238`, digest rules19 sin cambios. Las 18.110 filas siguen siendo medición `.1`, no `.2`; ambos códigos siguen sin publicarse.

El snapshot de trabajo actual `0.23.1-dev.20261108` añade hooks Codex/OpenCode ausentes de `.1` y `.2` congelados. Su aceptación se valida por separado. Las 18.110 filas y recibos de calidad congelados no se presentan como mediciones de esas adiciones del 8 de noviembre.

## Límites de interpretación

Los fixtures propios fueron escritos por autores de WARDEN y los ajenos se leyeron durante el desarrollo. El test de MCPTox es un **holdout histórico conocido**, no una prueba nueva nunca vista: sus resultados se publicaron y comparte plantillas con dev. Repetirlo no recupera la evaluación ciega. Afirmar independencia de reglas posteriores exige auditar procedencia; la ausencia de frases coincidentes no la demuestra por sí sola.

El archivo no establece comportamiento actual. Descubrimiento no evalúa ejecución ni seguridad de dependencias. Bloqueos estáticos no miden éxito de ataques contra modelos, protección completa o prevención de exfiltración. Experimentos con modelos, si se realizan, requieren modelo/versión, prompts, presupuesto, solicitudes y denominadores propios; no se desprenden de estas tablas estáticas.
