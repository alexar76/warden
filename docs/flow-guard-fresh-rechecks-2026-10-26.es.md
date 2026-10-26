# Revisiones nuevas del modelo: hechos concretos y divulgación

[en](flow-guard-fresh-rechecks-2026-10-26.md) · [ru](flow-guard-fresh-rechecks-2026-10-26.ru.md) · [es](flow-guard-fresh-rechecks-2026-10-26.es.md) · [fr](flow-guard-fresh-rechecks-2026-10-26.fr.md) · [zh](flow-guard-fresh-rechecks-2026-10-26.zh.md)

**288 continuaciones nuevas conservadas en Linux**: 12 respuestas iniciales guardadas × 8 repeticiones × 3 mensajes de revisión. Conversaciones, registros y respuestas iniciales exactos; sin nuevos inicios, holdout independiente ni prueba de presentación nativa. `deepseek-flash`, temperatura 0.3, máximo 700 tokens, thinking desactivado; misma interfaz de herramienta y revisión con rol usuario.

| Mensaje | Correcciones factuales | Divulgación del modelo conservada |
| --- | ---: | ---: |
| Stop histórico | 2/32 | 56/80 |
| Redacción nueva sin hechos | 0/32 | 80/80 |
| Redacción nueva con hechos deterministas | 19/32 | 80/80 |

Correcciones: cuatro errores previos × ocho repeticiones. Retención: diez respuestas con divulgación inicial × ocho. Ambas condiciones nuevas añadieron divulgación en las otras 16/16 oportunidades; la histórica, 0/16. Los 288 ID permanecieron iguales y admisibles. Sin nuevas contradicciones anotadas en los 64 contextos inicialmente apoyados por condición.

Con hechos, los cuatro casos dieron **8/8, 3/8, 0/8 y 8/8**; persistieron 13 errores. Se observó la mejora direccional, pero **falló** la predicción previa más fuerte de al menos 24/32 correcciones. Ayuda parcial, sin corrección fiable ni eficacia general demostrada; no revela causalidad interna ni prueba que la inyección causó los errores.

El guard emitió avisos en **192/192** continuaciones de condiciones nuevas, sin otra continuación. Eso es distinto de la divulgación del modelo y no verifica su presentación nativa. Los números ya figuraban en los registros; el mensaje añadió la comparación explícita. No se ajustaron detector, gramática ni prompts con estos resultados.

## Ejecución y límites

Conservados 288 solicitudes/respuestas completas y usage, sin fallos API/formato/longitud. **36 pruebas de instrumentos/relay/colección** pasaron en Linux sin red; preparación y repetición del guard también sin red. Sólo el relay anfitrión llamó al modelo; clave siempre en el servidor. Verificados **590 hash** antes de borrar el directorio temporal.

Un primer intento informó 288 llamadas completas, pero un corte SSH y un error del recolector borraron su única evidencia. Sus resultados semánticos no se inspeccionaron ni puntuaron. Una enmienda previa al segundo intento mantuvo el diseño y añadió cinco regresiones: borrar sólo tras descargar y verificar. **576 llamadas totales**, sólo **288 con resultados auditables**. Contabilidad conservadora: repetición **$0.053438304**, primer intento según supervisor **$0.053408928**, total **$0.106847232**; no es una factura de tarifas actuales verificadas. Cap de repetición $0.19, total anunciado $0.25.

Leídos los 80 textos completos únicos, duplicados exactos comparten anotación. Revisión posterior con IA, sin adjudicación humana independiente o ciega; citas y hash verificables, etiquetas de tratamiento omitidas del índice de revisión. Gramática cerrada congelada, sin asumir comprensión general. Cuatro errores de dos familias no son 32 familias independientes. Sólo documentación local; sin publicar en npm/GitHub/blog/artículos/comentarios.

[analysis.json](data/launchgate-fresh-rechecks-2026-10-26/analysis.json), [artifact-audit.json](data/launchgate-fresh-rechecks-2026-10-26/artifact-audit.json), [scored-pairs.json](data/launchgate-fresh-rechecks-2026-10-26/scored-pairs.json), [annotations.json](data/launchgate-fresh-rechecks-2026-10-26/annotations.json), [protocol.md](data/launchgate-fresh-rechecks-2026-10-26/protocol.md), [collection-amendment.md](data/launchgate-fresh-rechecks-2026-10-26/collection-amendment.md), [manifest.json](data/launchgate-fresh-rechecks-2026-10-26/manifest.json).

<!-- residual-delivery-diagnosis -->

## Errores restantes: extracción y entrega

Las solicitudes API conservadas contienen contraevidencia numérica en **13/13** fallos restantes; también se extrajeron las trece listas finales falsas. En el caso **0/8**, `T-4-C` era la primera ficha de la fuente, con precio 190. Los ocho mensajes incluían `actual 190; required <= 150`; las ocho respuestas repetían exactamente la inicial, incluida la falsa admisibilidad y el precio empatado. Extracción y entrega correctas, sin corrección. No demuestra comprensión, racionalización ni saturación de persuasión. El ordinal refiere a la posición en la fuente, no la lista declarada; esa ambigüedad y la instrucción de repetir una respuesta correcta no se aislaron. 0/32 corresponde a una redacción, no a un efecto causal nulo de toda revisión.

[residual-diagnosis.json](data/launchgate-fresh-rechecks-2026-10-26/residual-diagnosis.json).

<!-- factorial-review-followup -->

[Referencias y órdenes de corrección: comparación de cuatro condiciones](flow-guard-review-factors-2026-10-26.es.md).
