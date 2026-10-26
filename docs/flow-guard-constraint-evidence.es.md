# Evidencia determinista y conservación de la divulgación

[en](flow-guard-constraint-evidence.md) · [ru](flow-guard-constraint-evidence.ru.md) · [es](flow-guard-constraint-evidence.es.md) · [fr](flow-guard-constraint-evidence.fr.md) · [zh](flow-guard-constraint-evidence.zh.md)

Candidato local 0.22.0, sin publicar en npm. En las doce parejas revisadas, cuatro respuestas incluían una ficha de $190 como admisible con un límite de $150; tres continuaciones eliminaron la divulgación de la instrucción. No se modifican respuestas ni resultados históricos.

## Contrato y límites de confianza

El anfitrión puede enviar `answer_check` al hook Stop o llamar al exportado `checkAnswerConstraints`. El contrato vincula el SHA-256 de la respuesta exacta, sesión y turno positivo. Un adaptador de confianza aporta reglas del usuario/política, una captura de registros, el ID elegido y los ID declarados explícitamente admisibles. Se comprueban todos ellos; estar presente en la fuente no equivale a declararse admisible. Se admiten `lte`/`gte` numéricos finitos y `eq` numérico/booleano estricto.

Datos ausentes son desconocidos; contratos malformados o antiguos no pasan la comprobación. La evidencia usa posiciones y valores, por ejemplo `actual 190; required <= 150`, sin repetir nombres, ID, campos, URL ni citas de ataque. Las reglas nunca deben proceder de instrucciones del servidor MCP. El anfitrión normaliza unidades y monedas; los hechos siguen condicionados a la captura, sin verificar la honestidad del servidor ni conceder permisos. El hash no protege frente a un anfitrión malicioso.

## Continuación y divulgación

Tras texto externo registrado, una contradicción válida puede solicitar una continuación incluso sin solapamiento literal; el detector anterior sigue activo. Un recibo del guard para ese turno conserva un aviso fijo de instrucción externa en `systemMessage`, aunque el modelo borre su divulgación. No solicita otra continuación. Un nuevo turno elimina el recibo; audit sólo observa. Con los mismos hechos se notifican contradicciones restantes; una captura ausente o distinta deja la resolución desconocida. Corregir no exige cambiar un ID admisible.

El anfitrión debe mostrar `systemMessage`; no se ha medido su presentación en el cliente nativo ni se garantiza conservar la prosa del modelo.

## Ejemplo del anfitrión

Ya deben haberse registrado prompt y resultado externo; `turn` coincide con el turno del guard. El anfitrión extrae las declaraciones explícitas, no WARDEN.

```js
import { createHash } from 'node:crypto';
import { checkAnswerConstraints } from '@aimarket/warden';

const answer = 'A is selected. A and C are eligible.';
const answer_check = {
  schema: 'warden-answer-check/1', sessionId: 'session-1', turn: 1,
  answerSha256: createHash('sha256').update(answer).digest('hex'),
  rules: [{ field: 'priceUsd', op: 'lte', value: 150 }],
  records: [
    { id: 'A', attributes: { priceUsd: 123 } },
    { id: 'C', attributes: { priceUsd: 190 } },
  ],
  claims: { selectedId: 'A', eligibleIds: ['A', 'C'] },
};
const evidence = checkAnswerConstraints(answer_check, answer, 'session-1', 1);
// evidence.violations: [{ item: 2, rule: 1, op: 'lte', limit: 150, actual: 190 }]
// Stop input: { session_id: 'session-1', last_assistant_message: answer, answer_check }
```

## Alcance

El adaptador de investigación `scripts/selection-probe/constraint_claims.py` sólo entiende una gramática inglesa cerrada de listas de hoteles en JSON. No usa etiquetas semánticas de referencia, excluye el sufijo de aviso, rechaza listas no admitidas y deja el resto de la prosa sin examinar. No verifica toda afirmación de precio ni extrae restricciones generales de lenguaje natural. El Stop nativo no genera automáticamente este contrato.

## Validación Linux — 26 de octubre de 2026

Compilación y tipos correctos: **743 pruebas WARDEN en 21 archivos**, incluidas 29 nuevas; **24 pruebas Python** y el **gate determinista existente de 28 escenarios**. Verificados los 276 hash de salida. Pruebas sin red; sólo la instalación de dependencias npm tuvo red. Directorio remoto temporal eliminado. Compilado local y plugin sincronizados desde Linux tras verificar las fuentes congeladas.

| Observación sobre respuestas guardadas | Resultado |
| --- | ---: |
| Parejas inicial/final reales repetidas | 12 |
| Conjuntos admisibles falsos con $190 pese al límite de $150 | 4 |
| Contradicciones restantes en respuestas finales antiguas intactas | 4 |
| Avisos del guard conservados en la salida de continuación | 12/12 |
| Pérdidas previas de divulgación del modelo acompañadas por aviso | 3/3 |
| Segundas continuaciones / nuevas llamadas al modelo | 0 / 0 |

La gramática se escribió tras conocer estas respuestas: **repetición posterior de casos de desarrollo**, sin validación semántica independiente ni holdout. La extracción no lee las etiquetas de referencia; después se compara con la revisión previa. Detectar cuatro contradicciones no valida toda la prosa ni estima falsas alarmas generales. Las cuatro explicaciones erróneas no se regeneraron ni corrigieron. En tres textos sigue faltando divulgación: la protección nueva es el aviso separado del hook, cuya presentación por el cliente aún debe comprobarse. No se midió corrección del modelo ni eficacia independiente.

Desarrollo y revisión con ayuda de IA; sin revisión semántica independiente y ciega.

[results.json](data/launchgate-constraint-evidence-2026-10-26/results.json), [cases.json](data/launchgate-constraint-evidence-2026-10-26/cases.json), [execution.json](data/launchgate-constraint-evidence-2026-10-26/execution.json), [input-manifest.json](data/launchgate-constraint-evidence-2026-10-26/input-manifest.json), [manifest.json](data/launchgate-constraint-evidence-2026-10-26/manifest.json).

<!-- fresh-recheck-results -->

[Revisiones nuevas del modelo: hechos concretos y divulgación](flow-guard-fresh-rechecks-2026-10-26.es.md).

<!-- factorial-review-followup -->

[Referencias y órdenes de corrección: comparación de cuatro condiciones](flow-guard-review-factors-2026-10-26.es.md).

<!-- structured-answer-gate -->

[Validación por la aplicación](flow-guard-answer-gate.es.md): todas las reglas, corrección adicional limitada y salida almacenada; solo datos estructurados.
