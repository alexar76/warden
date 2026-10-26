# Prueba real del modelo con respuestas estructuradas

[en](flow-guard-structured-model-2026-10-26.md) · [ru](flow-guard-structured-model-2026-10-26.ru.md) · [es](flow-guard-structured-model-2026-10-26.es.md) · [fr](flow-guard-structured-model-2026-10-26.fr.md) · [zh](flow-guard-structured-model-2026-10-26.zh.md)

26 de octubre de 2026. WARDEN local **0.22.0**, sin cambios de runtime ni publicación npm. Continúa el [gate de la aplicación](flow-guard-answer-gate.es.md) y el [estudio de cuatro condiciones](flow-guard-review-factors-2026-10-26.es.md).

## Diseño y resultados

160 llamadas nuevas a `deepseek-flash` en Linux factory-vps, temperatura .3, thinking desactivado, JSON object mode, máximo 700 tokens de salida. El SDK real verifica todas las reglas, el conjunto completo de admisibles y el mínimo de precio; no se arreglan silenciosamente las propuestas.

Se conservan doce conversaciones originales, con instrucción externa y respuesta anterior en prosa. Una nueva petición exige reemplazarla con catálogo normalizado y cuatro campos estructurados. Ocho repeticiones por contexto producen **96 primeras propuestas válidas de 96**, incluidas **32/32** procedentes de los cuatro contextos antes contradictorios. Los ocho contextos restantes tenían explicaciones respaldadas. No hubo oportunidades naturales de reparación.

En una población separada, el experimentador introduce listas incorrectas: conjunto verdadero más C (190 > 150) o D (2.5 > 1). Son **semillas sintéticas**, no fallos espontáneos del modelo. En cuatro contextos y ocho repeticiones por tipo, **32/32 errores C y 32/32 errores D fueron corregidos en la primera reparación real**. La semilla consume la propuesta inicial del SDK, que permite hasta dos reparaciones; las tasas de esta población no se mezclan con las primeras propuestas naturales.

Las 160 propuestas nuevas no admitieron C/D, claves JSON duplicadas, formato inválido ni campos adicionales. Se emitieron **160 resultados verificados y 160 avisos de la aplicación**, sin candidatos no verificados ni errores API. No hubo sustitución C→D ni intentos descartados. Se cumplieron ambos pronósticos congelados: >=80/96 natural y >=48/64 controlado.

**Ningún caso necesitó la segunda reparación ni la retención.** Sus tasas con modelo real siguen sin medirse; las pruebas deterministas/stdio anteriores verifican el mecanismo. En cada trayectoria hubo una sola llamada real.

No se observó acumulación de la afirmación falsa en la superficie estructurada medida. El formato tiene una lista de admisibles, sin prosa, precio o exclusión redactados por el modelo. Cambiaron juntos contrato, catálogo e instrucción: no hay control contemporáneo de prosa, efecto causal exclusivo del formato ni conjunto independiente. Repetir doce contextos conocidos no demuestra fiabilidad general ni protección amplia frente a inyecciones.

## Auditoría, coste y límites

Los valores finales se recalcularon con los hechos originales sin usar el validador runtime. Se mide el frame capturado de salida, no la visualización en GUI nativa ajena. No se verifican verdad de la fuente, explicaciones libres, autorización de pagos/acciones ni influencia oculta entre opciones empatadas.

Antes de pagar pasaron **9 pruebas Node + 28 pruebas de relay/presupuesto/recogida** y 480 preflights de solicitudes. Contenedor Linux sin red/clave; solo el relay del host accede al endpoint oficial. Se conservaron todas las solicitudes/respuestas y verificaron **333 hashes** antes de borrar el directorio temporal. Sin reintentos automáticos ni repetición del estudio. No hizo falta cambiar código.

Todas las llamadas fueron fuera de hora punta. Usage: 211,200 tokens de entrada, 103,936 en caché; 17,946 de salida. Según la [tarifa publicada](https://api-docs.deepseek.com/quick_start/pricing/), **USD 0.027169008**; contabilidad conservadora de punta **USD 0.054338016**, por debajo del límite **USD 0.15**. Sin consulta de factura o variación de saldo; se utilizó el servidor existente.

Preparación/auditoría asistidas por IA y sin cegamiento; no se afirma revisión humana independiente. Sin publicación GitHub/npm ni comentario enviado.

[analysis.json](data/launchgate-structured-model-2026-10-26/analysis.json) · [protocol.md](data/launchgate-structured-model-2026-10-26/protocol.md) · [execution.json](data/launchgate-structured-model-2026-10-26/execution.json) · [output-audit.json](data/launchgate-structured-model-2026-10-26/output-audit.json) · [trajectories.jsonl](data/launchgate-structured-model-2026-10-26/trajectories.jsonl) · [manifest.json](data/launchgate-structured-model-2026-10-26/manifest.json)

<!-- prospective-holdout-followup -->

[Nuevos casos tras congelación](flow-guard-prospective-holdout-2026-10-26.es.md): primeras naturales válidas 89/96, cinco de siete reparadas y dos retenidas; controladas 45/48. Evidencia posterior de clasificación/conjunto incompleto probada offline, sin volver a llamar al modelo.
