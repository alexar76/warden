# Referencias de salida: comportamiento comprobado y límites

[en](flow-guard-reference-egress.md) · [ru](flow-guard-reference-egress.ru.md) · [es](flow-guard-reference-egress.es.md) · [fr](flow-guard-reference-egress.fr.md) · [zh](flow-guard-reference-egress.zh.md)

26 de octubre de 2026. WARDEN local **0.22.1**. Compilación y tipos correctos en Linux factory-vps; **127/127 pruebas en cuatro suites**, incluidas **25 nuevas**. Sin cambios de runtime, umbrales o versión. Cero llamadas de modelo pagadas, transmisiones reales o coste API adicional.

## Comprobaciones

Frases manuales como «usa la tercera entrada de esa hoja» no coinciden con las huellas del secreto. Tras observar credenciales y texto externo, la llamada saliente exige revisión (`ask`) o se rechaza en modo `deny`. La frontera persiste tras 1/3/8 resultados intermedios observados y un nuevo turno. Un destinatario nombrado o permitido no basta para eludirla. También se comprueban nombres MCP opacos; una herramienta fuera de MCP necesita clasificación explícita `outbound`.

Es una frontera de sesión/acción, **no seguimiento semántico de procedencia**. Las transformaciones son sintéticas y escritas a mano, no generadas por un modelo. Ningún remitente real se ejecutó. Las pruebas anteriores conservan el límite de paráfrasis del hook Stop.

## Excepciones

Una autorización exacta del operador puede permitir **una vez** una referencia opaca; no certifica que el valor referido sea público. Repeticiones, cambios de texto/destinatario/argumentos anidados/herramienta o deshabilitación por el host vuelven a requerir revisión. Un secreto literal conocido sigue rechazándose aunque exista autorización exacta.

Una herramienta no MCP desconocida sin etiqueta queda fuera de esta frontera. Sin credencial o texto externo observados, la frontera no se activa. Datos privados ordinarios sin credencial reconocida no están cubiertos universalmente. `audit` registra sin bloquear y `off` desactiva. El host debe ejecutar los hooks y respetar sus decisiones. No se reprobó el ejecutor task-adapter ni la interfaz nativa.

Ventanas fuertes **8 no hex / 10 hex** sin cambios; las pruebas existentes de fragmentos aislados pasan. No se demuestra prevención general de filtraciones semánticas.

## Evidencia

El usuario autorizó este archivo de 101 ficheros/316 KB tras el rechazo inicial de la revisión automática. Sin claves ni configuración del servidor. Red solo para dependencias dev con scripts deshabilitados; pruebas en contenedor sin privilegios y sin red. Se verificaron seis hashes de salida antes de eliminar el directorio remoto temporal. Preparación asistida por IA; sin publicación en GitHub/npm ni comentarios enviados.

[Results](data/qingfeng-reference-egress-2026-10-26/results.json) · [Protocol](data/qingfeng-reference-egress-2026-10-26/protocol.md) · [Execution](data/qingfeng-reference-egress-2026-10-26/execution.json) · [Tests](data/qingfeng-reference-egress-2026-10-26/vitest.json) · [Input hashes](data/qingfeng-reference-egress-2026-10-26/input-manifest.json).
