# Validación estructurada bajo control de la aplicación

[en](flow-guard-answer-gate.md) · [ru](flow-guard-answer-gate.ru.md) · [es](flow-guard-answer-gate.es.md) · [fr](flow-guard-answer-gate.fr.md) · [zh](flow-guard-answer-gate.zh.md)

Candidato local **0.22.0**, 26 de octubre de 2026; sin publicación en npm. Sigue al [estudio de cuatro condiciones](flow-guard-review-factors-2026-10-26.es.md): eliminar el error de precio de C a veces introdujo el error de distancia de D. Quitar una contradicción no demuestra corrección completa.

## Contrato y alcance

`createAnswerGate`, exportado desde `@aimarket/warden`, requiere integración explícita. La aplicación controla las reglas del usuario/política, los registros normalizados, sesión/turno, generación y salida final; almacena los candidatos antes de mostrarlos. Las instrucciones de un servidor externo nunca deben definir las reglas.

El catálogo sustituye ID y nombres originales por referencias `rec-…` y campos `field_1`. La evidencia identifica registro, campo, valor real y límite, sin copiar nombres, URL ni instrucciones externas. `referenceForRecord(sourceId)` es un mapa para la aplicación. El SHA-256 vincula sesión, turno, datos, reglas y clasificación; reordenar registros conserva las referencias.

La propuesta contiene exactamente `schema: "warden-selection/1"`, `catalogSha256`, `selectedRef` y `eligibleRefs`. Véanse JSON y API en la [versión inglesa](flow-guard-answer-gate.md).

Cada propuesta vuelve a verificar **la selección y todas las alternativas admitidas contra todas las reglas**, el conjunto completo de admisibles y el mínimo/máximo numérico opcional. Se permiten empates óptimos. Operadores: `lte`/`gte` numéricos finitos y `eq` numérico/booleano estricto. Datos necesarios ausentes o mal tipados, contrato obsoleto, referencias desconocidas, claves JSON duplicadas, prosa y campos adicionales nunca autorizan la entrega. Si no hay admisibles, se retiene el resultado.

La salida solo contiene datos estructurados verificados; sus atributos proceden de la instantánea de la aplicación. No verifica explicaciones arbitrarias, fechas, geografía, verdad del origen ni influencia oculta sobre preferencias. La aplicación normaliza unidades y elige reglas. Un resultado permitido no autoriza pagos, acciones ni herramientas.

## Bucle limitado y entrega

`gate.run({ generate, emit, maxCorrections: 2, timeoutMs: 30000 })` permite una propuesta inicial y **dos correcciones como máximo**, una pasada adicional respecto al diseño de una corrección. Tras C→D, la siguiente evidencia identifica `2.5 > 1` en D. Al agotar el límite se emite `WARDEN_RESULT_WITHHELD`, sin reenviar el candidato inválido. Solo se admiten límites 0/1/2.

Cada instancia reserva una ejecución/salida. Fallos de generación, cancelación o tiempo agotado no reintentan automáticamente; una respuesta tardía no se publica. El adaptador debe respetar `signal` para detener su trabajo. Una entrega incierta no se reenvía. La aplicación conserva la propiedad de solicitudes entre instancias y evita transmitir candidatos o registros no verificados al usuario.

El aviso fijo de la aplicación no depende de la cooperación del modelo. `disclosure: "source-instructions"` exige evidencia de instrucciones detectadas; por defecto se informa del uso de registros externos. La aplicación debe mostrar el aviso. El [ejemplo stdio](../examples/answer-gate-host.mjs), con `--contract host-owned.json`, lee propuestas de stdin, escribe catálogo/evidencia en stderr y solo resultado final verificado o rechazo en stdout. No llama al modelo, API o herramientas.

**El Stop-hook ordinario no controla la pantalla final.** Conserva una continuación. La retención requiere integrar el SDK y almacenar la salida. La prueba de nuestra propia aplicación stdio no verifica la interfaz de clientes nativos ajenos.

## Verificación y límites

Evidencia en `docs/evidence/launchgate-answer-gate-2026-10-26/` del monorepositorio. Compilación y pruebas en Linux factory-vps; sin nuevas llamadas al modelo. Se comprueban C→D→resultado válido, retención de D persistente, conjuntos completos, clasificación, empates, datos desconocidos/obsoletos, metadatos hostiles, cancelación, tiempos límite, concurrencia, entrega incierta y stdout de un proceso real.

La repetición histórica transforma únicamente listas de admisibilidad explícitamente anotadas de 384 respuestas conservadas. La prosa no soportada permanece desconocida. Rechazar una lista falsa codificada no demuestra comprensión automática de prosa, reparación por el modelo ni seguridad sobre un conjunto independiente. No se modifican respuestas ni resultados anteriores.

Leímos un diálogo completo del caso persistente: el mismo texto declara C admisible a $129 y excluido a $190. Es una contradicción observable, no prueba de su causa interna. Preparación y revisión asistidas por IA; sin revisión independiente ciega.

<!-- verified-answer-gate-results -->

Verificado en Linux factory-vps: compilación/tipos, **791 pruebas en 24 suites**, incluidas **43 del gate/stdio**, y los 28 escenarios red-team existentes. De 384 proyecciones históricas: 50 listas falsas rechazadas, 75 válidas permitidas y 259 respuestas de prosa no soportada desconocidas; ningún candidato no verificado fue entregado. Son proyecciones de anotaciones, no nuevas correcciones del modelo. Se verificaron 289 hashes y sincronizaron 276 archivos locales compilados en Linux. Se conservan los dos intentos anteriores con errores sintácticos en pruebas.

[results.json](data/launchgate-answer-gate-2026-10-26/results.json) · [execution.json](data/launchgate-answer-gate-2026-10-26/execution.json) · [historical-replay.json](data/launchgate-answer-gate-2026-10-26/historical-replay.json) · [stubborn-transcript.json](data/launchgate-answer-gate-2026-10-26/stubborn-transcript.json) · [manifest.json](data/launchgate-answer-gate-2026-10-26/manifest.json)
