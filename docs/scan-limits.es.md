# Límites de medición y pruebas de versión

> 🌐 [English](scan-limits.md) · [Русский](scan-limits.ru.md) · **Español** · [Français](scan-limits.fr.md) · [中文](scan-limits.zh.md)

Estas precisiones corresponden al seguimiento de comentarios del 2026-10-25. El **artefacto npm publicado `0.21.0`** y el código local posterior son objetos distintos: conservar la versión en `package.json` no incorpora una corrección al archivo publicado. Las pruebas de código, la facturación ficticia y las respuestas programadas de aprobación no sustituyen las evaluaciones de modelos, el tráfico de producción ni los estudios con personas.

## Facturación y declaraciones del servidor

`initialize`, `tools/list` y una llamada canary pueden generar cargos u otros efectos en el servidor. Un descubrimiento o preview correcto no demuestra el precio ni el efecto de la siguiente llamada. En nuestra fixture de facturación sintética, el canary elegía `preview` gratuito, mientras que `{}` elegía una operación que cobraba siete créditos ficticios. Esto mide esa fixture, no la factura de un vendedor externo.

`readOnlyHint`, `destructiveHint` y `openWorldHint` son declaraciones no verificadas; no prueban gratuidad ni ausencia de efectos dañinos. La revisión local de annotations en el primer uso es opcional, está en `off` por defecto y solo se aplica a `wrap --flow NAME`. Aceptarla no aprueba un precio ni certifica efectos. Véanse los [controles de flujo y sus límites](flow-guard.es.md).

## Versión solicitada del paquete y versión declarada del servidor

`package@x.y.z` especifica una versión solicitada del paquete. El servidor proporciona `initialize.serverInfo.version`; no es una versión de paquete resuelta de forma independiente ni un digest del artefacto. Por ejemplo, el paquete Mapled revisado era `@mapled/mcp@0.21.6`, pero el servidor seguía declarando `0.1.0`.

El `0.21.0` publicado que se probó podía usar incorrectamente esa versión declarada en una sugerencia de fijación del paquete. Compruebe la resolución del gestor de paquetes y las pruebas de lock/integridad en lugar de aceptar esa sugerencia. La corrección local separa los metadatos y elimina esa sustitución; sigue sin certificar qué bytes ejecutó el launcher. Un `npx` sin versión fija puede resolver otra versión o reutilizar la caché; ningún comportamiento está garantizado en cada inicio. El hash de tools identifica las definiciones observadas, no el programa completo. Véanse [scan](scan.es.md) e [integración](integration.es.md).

## Comparaciones de launchers y referencias orientativas

La investigación de Auten contaba con una instantánea pública observada, no con dos entornos de launcher medidos. Reproducir una diferencia requiere el runner y su versión exactos, los argumentos de inicio y dos instantáneas de tools de los entornos afectados. Una observación de HISTOR es una referencia orientativa para comparar, no un pin de confianza aprobado por el operador.

La documentación auxiliar del [colector de pruebas del launcher](../examples/launcher-evidence/README.md) está actualmente solo en inglés. Guarda definiciones de tools normalizadas por el cliente, no una transcripción original del protocolo. La versión indicada del runner la declara el propietario; ese campo no resuelve de forma independiente el artefacto del paquete. Tener preparado el colector no demuestra que se compararon los dos entornos.

## Preguntas, aprobaciones y respuestas

El **39/97** histórico cuenta tareas que provocaron un `ask`, no personas que aprobaron. La ejecución después de una decisión del hook no prueba que alguien pulsara Allow. El wrapper puede registrar accept/decline/cancel, pero un cliente programado puede producir las mismas respuestas. Las tasas de aprobación humana, el tiempo de lectura y la fatiga requieren solicitudes realmente presentadas a personas y resultados vinculados; estas pruebas no los midieron.

Para la serie guardada de DeepSeek Flash guard + note (`injecagent`, 20 casos de travel), el resultado histórico oficial de AgentDojo sigue siendo **18/20** según su predicado de mención exacta del nombre. La lectura asistida por IA encontró advertencias y no recomendaciones adoptadas en los fragmentos guardados, pero solo 18 respuestas estaban completas; dos alcanzaron el antiguo límite de 2000 caracteres. Se desconocen sus finales, por lo que no se establece un nuevo resultado `0/20` sobre respuestas completas. El harness local guarda las futuras respuestas completas con longitud y hash; no recupera texto perdido ni implica una nueva ejecución del modelo.

## Umbrales de fragmentos y coste de revisión

Las ventanas fuertes de fingerprint siguen siendo **8 para non-hex / 10 para hex**. La corrección local del índice tras prefijos reconocidos no demuestra una detección fuerte fiable de fragmentos de seis caracteres dentro de palabras. Una sesión existente debe releer las credenciales para incorporar las nuevas ventanas. Pedir revisión en el límite de credenciales no equivale a identificar ese fragmento como secreto.

Del mismo modo, la coincidencia de 12 caracteres normalizados en Stop solicita otra revisión de la respuesta; no demuestra rechazo semántico de una instrucción. Al eliminar la excepción de palabras de advertencia, una advertencia honesta también paga ese paso. Las paráfrasis y la selección manipulada de filas pueden eludir esta coincidencia. Las mejoras en fixtures y los controles elegidos de falsos bloqueos no demuestran un óptimo global ni una tasa de falsos positivos en producción. La [guía de flujo](flow-guard.es.md) explica la política, los límites restantes y la continuación limitada por el indicador `stop_hook_active` del host.
