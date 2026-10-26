# Host-owned structured answer gate

<!-- final-ranking-witness -->
**[Final ranking-feedback comparison, 26 October](flow-guard-final-witness-2026-10-26.md).** On all five previously withheld contexts, old feedback repaired 6/40 continuations and explicit selected-versus-best feedback repaired 40/40. Valid controls stayed valid 20/20 per nominal arm. This completes the series on selected known failures, not a new holdout. The earlier offline-only statement is superseded for ranking feedback on this cohort; missing-set feedback efficacy remains unmeasured.
<!-- /final-ranking-witness -->

[en](flow-guard-answer-gate.md) · [ru](flow-guard-answer-gate.ru.md) · [es](flow-guard-answer-gate.es.md) · [fr](flow-guard-answer-gate.fr.md) · [zh](flow-guard-answer-gate.zh.md)

Local candidate **0.22.0**, 26 October 2026. Not published to npm. This opt-in host SDK follows the [four-condition continuation study](flow-guard-review-factors-2026-10-26.md). Removing C's price error sometimes introduced D's distance error: removing one contradiction did not establish a correct explanation.

## Ownership and supported output

`createAnswerGate` is exported from `@aimarket/warden`. The integrating application owns the actual user/policy rules, normalized captured records, session/turn, generation callback and final display. It must buffer candidates and use the gate's output boundary. A tool server's instructions must never become the constraint contract.

The catalog replaces arbitrary source IDs and field names with safe `rec-…` references and `field_1` handles. Feedback identifies the exact record and field, actual value and required bound, without copying source names, URLs or instruction fragments. `referenceForRecord(sourceId)` is a host-only mapping. The digest binds the session, turn, complete normalized facts, rules and optional ranking; reordered records retain their references.

The model proposal has exactly four fields:

```json
{"schema":"warden-selection/1","catalogSha256":"<catalog digest>","selectedRef":"rec-<24 hex characters>","eligibleRefs":["rec-<24 hex characters>"]}
```

The gate checks the selected record and **every admitted alternative against every declared rule**, the complete eligible set, and an optional numeric min/max ranking. Either equally optimal record is admissible. Rules support finite numeric `lte`/`gte` and strict numeric/boolean `eq`. Missing or incorrectly typed necessary facts, stale contracts, unknown references, duplicate JSON keys, unsupported prose and extra fields never become an allow. No eligible records produces a withholding notice.

Only a checked structured result is rendered. Prices/attributes in that result come from the frozen host snapshot, not model prose. This deliberately does **not** validate arbitrary explanations, dates, locations, source truth, hidden preference influence or all possible task constraints. The host must normalize units and choose the correct rules. No payment, action or tool authorization follows from an allowed answer.

## Bounded correction and final boundary

```js
import { createAnswerGate } from '@aimarket/warden';

const gate = createAnswerGate({
  sessionId: 'host-owned-session', turn: 1,
  disclosure: 'source-instructions',
  rules: [
    { field: 'price', op: 'lte', value: 150 },
    { field: 'distance', op: 'lte', value: 1 }
  ],
  records: [
    { id: 'A', attributes: { price: 129, distance: 0.6 } },
    { id: 'C', attributes: { price: 190, distance: 0.6 } },
    { id: 'D', attributes: { price: 129, distance: 2.5 } }
  ],
  ranking: { field: 'price', direction: 'min' }
});

await gate.run({
  maxCorrections: 2, timeoutMs: 30000,
  generate: async ({ catalog, feedback, signal }) => {
    // Your host model adapter returns ONLY the structured proposal string.
    // Pass the frozen catalog, latest feedback and cancellation signal.
    return modelAdapter({ catalog, feedback, signal });
  },
  emit: rendered => displayBufferedHostResult(rendered)
});
```

The default is one initial proposal and at most **two corrections**: one bounded extra pass beyond a one-correction design. Every new proposal is checked again against the entire frozen contract. If C is removed but D is admitted, the next feedback reports D's `2.5 > 1` violation. After the limit the host emits `WARDEN_RESULT_WITHHELD`, never the rejected candidate. `maxCorrections` may be 0, 1 or 2; no unbounded loop is available.

One gate instance reserves one run/output. Generation failure, timeout or cancellation causes no automatic provider retry; late completions cannot publish. The callback must honor `signal` to stop its own outstanding work. An uncertain output failure is not resent. Applications must maintain their own request ownership across gate instances and avoid streaming unverified candidates or externally exposing callback logs.

The fixed host notice is part of the final output regardless of model cooperation. Select `source-instructions` only when the host has evidence that instructions were found; the default states that external records were used. The application must actually display the notice. The runnable [stdio host](../examples/answer-gate-host.mjs) accepts `--contract host-owned.json`, reads proposal lines on stdin, writes request/catalog/feedback on stderr and only the final checked payload or withholding notice on stdout. It makes no model/API/tool calls itself.

**This does not turn an ordinary Stop hook into an output owner.** Existing hooks still request only one continuation. Applications must explicitly integrate the SDK and buffer final delivery. Our stdio integration test does not establish rendering in third-party native clients.

## Verification and limits

The evidence and test receipts are in `docs/evidence/launchgate-answer-gate-2026-10-26/` in the monorepo. Tests cover C → D → valid output, unresolved D withholding, complete sets/ranking/ties, unknown input, stale state, hostile source metadata, cancellation, timeouts, concurrent calls, uncertain delivery and actual child-process stdout. Build and tests run on Linux factory-vps, not the Mac. No new model calls are part of this offline verification.

The historical replay projects explicitly reviewed eligibility lists from 384 retained answers into the new schema. Unsupported prose remains unknown. Rejecting an encoded false list is a validator result, **not** automatic prose understanding, a fresh repair experiment or a held-out security result. The original model outputs and study results remain unchanged.

We also retained and read a complete stubborn-case transcript: its final explanation both lists C as eligible at $129 and excludes C because it costs $190. This supports an observable internal contradiction in the answer, not a conclusion about hidden reasoning or why a wording change failed. Preparation and review used AI assistance; no independent blinded review is claimed.

<!-- verified-answer-gate-results -->

Verified on Linux factory-vps: build/typecheck, **791 tests in 24 suites**, including **43 gate/stdio tests**, plus the existing 28-scenario red-team gate. Across 384 historical projections: 50 false explicit lists denied, 75 valid explicit lists allowed, 259 unsupported prose answers unknown; no unverified candidate forwarded. These are post-hoc structured projections, not new model correction results. Verified 289 output hashes and synchronized 276 Linux-generated local files. Both earlier test-syntax failures are retained in the evidence directory.

[results.json](data/launchgate-answer-gate-2026-10-26/results.json) · [execution.json](data/launchgate-answer-gate-2026-10-26/execution.json) · [historical-replay.json](data/launchgate-answer-gate-2026-10-26/historical-replay.json) · [stubborn-transcript.json](data/launchgate-answer-gate-2026-10-26/stubborn-transcript.json) · [manifest.json](data/launchgate-answer-gate-2026-10-26/manifest.json)

<!-- structured-live-followup -->

[Live structured-model test](flow-guard-structured-model-2026-10-26.md): 96 valid first proposals and 64 controlled-seed repairs; separate denominators and limits.

<!-- prospective-holdout-followup -->

[Prospective new-fixture results](flow-guard-prospective-holdout-2026-10-26.md): 89/96 natural first proposals valid, five of seven repaired, two withheld; controlled repair 45/48. Separate post-hoc ranking/missing-set facts passed offline checks, without a new model run.
