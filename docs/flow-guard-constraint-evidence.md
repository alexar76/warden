# Deterministic answer evidence and disclosure continuity

[en](flow-guard-constraint-evidence.md) · [ru](flow-guard-constraint-evidence.ru.md) · [es](flow-guard-constraint-evidence.es.md) · [fr](flow-guard-constraint-evidence.fr.md) · [zh](flow-guard-constraint-evidence.zh.md)

Local candidate 0.22.0; not published to npm. This change follows the twelve-pair justification review. Four answers included a $190 record in the eligible set despite a $150 cap; three model continuations removed instruction disclosure. Historical answers and outcomes are unchanged.

## What the runtime checks

The host may supply an optional `answer_check` object to the Stop hook, or call the exported `checkAnswerConstraints` helper. The object binds the exact answer SHA-256, session and positive turn number. A trusted host adapter supplies user/policy constraints, a captured record snapshot, the selected ID and explicit positive eligibility claims. Rules support finite numeric `lte`/`gte` and strict numeric/boolean `eq`.

Every claimed eligible item is checked, including the selected item. A valid selection does not excuse an invalid eligible alternative. A record merely present in the source is not automatically claimed eligible. Missing fields/IDs remain unknown; malformed or stale envelopes are invalid, never a passed check. Evidence reports a positional item/rule number and finite values, such as `actual 190; required <= 150`, without echoing source names, IDs, field labels, URLs or attack quotes.

Rules must come from the real user or operator policy. Never forward server-authored `answer_check` objects as trusted host input. Normalize currencies, units and field meaning before checking. Record facts remain conditional on their captured source; this mechanism neither verifies a lying server nor grants permissions. Hash binding prevents accidental answer/snapshot mixups, not a malicious host.

## Stop and disclosure

After recorded outside text, a validated contradiction can request one Stop continuation even without a literal instruction overlap. Existing overlap checks still apply. A guard-owned same-turn receipt preserves a fixed source-instruction notice in the continuation hook output even if the model deletes its own disclosure. The hook does not request another continuation. New user turns clear the receipt; audit mode remains observational.

An unchanged facts digest permits reporting remaining contradictions. A missing or changed snapshot leaves resolution unknown. Correction may retain the selected ID when that choice remains admissible. Keeping the notice in hook output is distinct from preserving the model's own prose: the host must display `systemMessage`; native-client rendering has not been measured here.

## Host contract example

The example below assumes a prompt and outside-tool-result event have already been recorded. `turn` must match the guard's current turn. The host extracted the explicit eligible set from this exact answer; WARDEN does not infer arbitrary prose.

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

## Adapter scope and evidence

The repository-only `scripts/selection-probe/constraint_claims.py` adapter understands a closed English eligibility-list grammar in the synthetic hotel answer JSON. It extracts claims without semantic gold labels, strips the canonical warning suffix, rejects unsupported eligibility-list forms, and labels other prose unexamined. It does not validate every price assertion, infer arbitrary numeric constraints from prose, or ship as a general NLP adapter. The ordinary native Stop input does not automatically provide this optional contract.

## Linux validation — 26 October 2026

Build and typecheck passed, together with **743 WARDEN tests in 21 files** (including 29 new constraint/continuation tests), **24 Python instrument tests** and the existing **28-scenario deterministic gate**. All 276 collected output hashes were verified. Runtime checks had no network; only npm dependency installation had network. The temporary remote root was removed. The local build and plugin were synchronized from these Linux-generated outputs, after rechecking frozen source hashes.

| Saved-answer observation | Result |
| --- | ---: |
| Actual initial/final pairs replayed | 12 |
| Explicit eligible sets with a $190 item despite the $150 limit | 4 |
| Same contradictions still present in the unchanged old final answers | 4 |
| Continuation hook outputs retaining the guard instruction notice | 12/12 |
| Prior model-text disclosure losses accompanied by that guard notice | 3/3 |
| Second continuations requested / new model calls | 0 / 0 |

The adapter's grammar was written after seeing these saved answers; this is **post-hoc development-case replay**, not independent semantic validation or a holdout. It independently extracts claim lists at execution time without reading the gold labels, then the replay compares detections with the earlier audit. Finding all four contradictions does not validate all prose or establish a general false-positive rate. The four original wrong explanations were not regenerated or corrected in this replay. Three model prose disclosures remain absent: the new safeguard is an independently emitted hook notice, whose client-side display must still be verified. New model correction and held-out efficacy remain unmeasured.

Development and review used AI assistance; no independent blinded semantic review is claimed.

[results.json](data/launchgate-constraint-evidence-2026-10-26/results.json), [cases.json](data/launchgate-constraint-evidence-2026-10-26/cases.json), [execution.json](data/launchgate-constraint-evidence-2026-10-26/execution.json), [input-manifest.json](data/launchgate-constraint-evidence-2026-10-26/input-manifest.json), [manifest.json](data/launchgate-constraint-evidence-2026-10-26/manifest.json).

<!-- fresh-recheck-results -->

[Fresh model rechecks: concrete facts and disclosure](flow-guard-fresh-rechecks-2026-10-26.md).

<!-- factorial-review-followup -->

[Record references and correction directives: a four-condition model test](flow-guard-review-factors-2026-10-26.md).

<!-- structured-answer-gate -->

[Host-owned answer gate](flow-guard-answer-gate.md): all constraints, bounded extra correction and buffered final delivery; structured data only.
