# Referencias y órdenes de corrección: comparación de cuatro condiciones

[en](flow-guard-review-factors-2026-10-26.md) · [ru](flow-guard-review-factors-2026-10-26.ru.md) · [es](flow-guard-review-factors-2026-10-26.es.md) · [fr](flow-guard-review-factors-2026-10-26.fr.md) · [zh](flow-guard-review-factors-2026-10-26.zh.md)

**384 continuaciones nuevas conservadas en Linux**, con plan 2×2 congelado: 12 contextos iniciales exactos × 8 repeticiones × 4 mensajes. Cambios en el adaptador de investigación, no en el runtime publicado. `deepseek-flash`, temperatura 0.3, máximo 700 tokens, thinking desactivado. Se usa el control nuevo de esta ejecución, no el anterior 19/32.

| Referencia / petición | Correcciones completas | D declarado admisible por error |
| --- | ---: | ---: |
| Ordinal / condicional | 22/32 | 0/32 |
| Registro explícito / condicional | 25/32 | 4/32 |
| Ordinal / orden directa | 14/32 | 5/32 |
| Registro explícito / orden directa | 17/32 | 14/32 |

Cuatro errores conocidos × ocho repeticiones por condición. Una corrección completa no puede conservar ni introducir otra contradicción verificable. Todos los ID quedaron iguales y admisibles. Sin nuevas contradicciones en los 64 controles inicialmente apoyados por condición; sus mensajes son idénticos entre tratamientos.

La combinación retiró el error original de C en **31/32**, pero 14 respuestas admitieron D a **2.5 km con límite de 1 km**: sólo **17/32** correcciones completas. Cinco respuestas ordinal/directa añadieron una exclusión correcta de C sin borrar su afirmación falsa anterior; no pasan. Una respuesta conjunta negó explícitamente el precio verdadero de $190. Son diagnósticos posteriores, no mecanismos internos demostrados.

El antiguo caso 0/8 dio **1/8, 2/8, 0/8, 1/8**. Fallaron ambas predicciones fuertes previas: conjunto ≥24/32 y ese caso ≥4/8. Presentación explícita: +9.375 puntos a cada forma de petición; orden directa: −25 puntos a cada referencia. Interacción observada cero. Cuatro casos de dos familias, sin inferencia poblacional ni significación general. La referencia explícita combina ID, campo/valor y consecuencia; no aísla sólo resolver ID. Estos datos no justifican sustituir la revisión condicional por la orden probada. Runtime, gramática y prompts no se ajustaron con los resultados.

## Divulgación y ejecución

Cada condición retuvo divulgación **80/80** y la añadió **16/16**. El guard emitió avisos **384/384**, sin otra continuación; presentación nativa sin medir. Pasaron **44 pruebas offline** de instrumentos/relay/colección. Guard y pruebas sin red; sólo relay anfitrión con API, clave en servidor. 384 solicitudes/respuestas completas, cero errores; **783 hash** verificados antes de limpiar. Contabilidad conservadora **$0.074455776**, cap $0.12; no factura actual verificada. Total con el estudio previo separado y su intento perdido: $0.181303008, sin combinar resultados.

Revisión de **161 textos únicos**: 19 coincidencias exactas con revisión anterior, 142 textos nuevos completos leídos. Citas/hash y hechos verificados; etiquetas omitidas del índice. Revisión posterior con IA, no humana independiente/ciega; ninguna causalidad interna inferida. Gramática congelada, sin validación semántica universal ni holdout independiente. Sólo documentos locales, ninguna publicación npm/GitHub/blog/artículo/comentario.

| Caso inicial | Ordinal/condicional | Explícito/condicional | Ordinal/directo | Explícito/directo |
| --- | ---: | ---: | ---: | ---: |
| tie-2 / original 0 | 7/8 | 8/8 | 0/8 | 0/8 |
| tie-4 / original 3 | 6/8 | 7/8 | 6/8 | 8/8 |
| tie-4 / original 5 | 1/8 | 2/8 | 0/8 | 1/8 |
| tie-4 / original 7 | 8/8 | 8/8 | 8/8 | 8/8 |

[analysis.json](data/launchgate-review-factors-2026-10-26/analysis.json), [artifact-audit.json](data/launchgate-review-factors-2026-10-26/artifact-audit.json), [scored-pairs.json](data/launchgate-review-factors-2026-10-26/scored-pairs.json), [annotations.json](data/launchgate-review-factors-2026-10-26/annotations.json), [protocol.md](data/launchgate-review-factors-2026-10-26/protocol.md), [manifest.json](data/launchgate-review-factors-2026-10-26/manifest.json).

<!-- structured-answer-gate -->

[Validación por la aplicación](flow-guard-answer-gate.es.md): todas las reglas, corrección adicional limitada y salida almacenada; solo datos estructurados.
