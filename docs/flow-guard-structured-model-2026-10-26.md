# Live model test of the structured answer boundary

[en](flow-guard-structured-model-2026-10-26.md) · [ru](flow-guard-structured-model-2026-10-26.ru.md) · [es](flow-guard-structured-model-2026-10-26.es.md) · [fr](flow-guard-structured-model-2026-10-26.fr.md) · [zh](flow-guard-structured-model-2026-10-26.zh.md)

26 October 2026. Unchanged local WARDEN **0.22.0**, not published to npm. Follow-up to the [host-owned answer gate](flow-guard-answer-gate.md) and [four-condition prose study](flow-guard-review-factors-2026-10-26.md).

## What was run

160 fresh `deepseek-flash` calls on Linux factory-vps, temperature .3, thinking disabled, JSON object mode, maximum 700 output tokens. The actual frozen `createAnswerGate` build validated each proposal against every rule, the complete eligible set and minimum-price ranking. No model proposal was silently edited into a passing answer.

The twelve saved contexts retain their original tool conversation, untrusted source instruction and original prose answer. A new user request asks for complete replacement using a normalized catalog and the four-field structured contract. Eight repetitions per context give 96 natural transitions. Four contexts originally had contradicted explanations; eight were supported. This output contract/catalog/instruction bundle is a changed task, not a format-only ablation.

Separately, for the four contradicted contexts, we deliberately seeded the true eligible set plus either C (190 > 150 price cap) or D (2.5 > 1 distance bound), with eight repetitions per case/type. These **64 synthetic initial errors** are not spontaneous new model failures. They consume the initial SDK proposal; at most two fresh repairs remain. Natural trajectories permit an initial fresh proposal and at most two repairs. The two populations are never pooled into one correction rate.

## Results

| Population | Result |
|---|---|
| Natural transitions | **96/96 valid first proposals**; no natural repair opportunities |
| Four formerly contradicted contexts | **32/32 valid first proposals**, included in the 96 |
| Controlled C seeds | **32/32 corrected after one fresh repair** |
| Controlled D seeds | **32/32 corrected after one fresh repair** |
| Fresh proposals admitting C/D, malformed/duplicate JSON or extra fields | **0/160** |
| Final captured host frames | **160 checked results, 160 notices, zero unverified candidates** |

Both frozen predictions were met: >=80/96 natural first-valid and >=48/64 controlled final-valid. Every trajectory used one actual API call. No API errors, C→D substitutions or discarded attempts occurred. **No trajectory needed a second repair or live withholding**, so this experiment cannot estimate those paths' live-model success rates. Their earlier deterministic and actual stdio tests remain the evidence for mechanism behavior.

The addendum failure was not observed on this structured surface. The schema has one eligible-list field and no model-authored price, exclusion or reason field. This does not measure arbitrary contradictory prose or prove that the model cannot produce it. The normalized catalog and more explicit instruction changed alongside the schema; no contemporaneous prose control or independent holdout was run. Repetitions share twelve known contexts, so 160/160 is not a general reliability guarantee or proof of broad prompt-injection resistance.

## Delivery, audit and cost

The host independently supplied its fixed notice and emitted only validated structured selections/attributes. All final values were recalculated against the original fixture by the collected-data audit without invoking the runtime validator. The captured frame is the measured host boundary; rendering in a third-party native GUI remains untested. Source truth, arbitrary explanations, payment/action authorization and hidden tie-preference influence are outside this result.

Before calls, 9 Node harness tests and 28 relay/budget/collection tests passed on Linux, plus 480 request preflights. The runner had no network or credential; only the host-local relay reached the fixed official endpoint. All requests/responses were retained and 333 output hashes verified before deleting the owned temporary root. No transport retries or repeated study. No runtime code change was needed.

All calls occurred outside peak hours. Provider-reported usage: 211,200 input tokens (103,936 cached), 17,946 output tokens. At the [published tariff](https://api-docs.deepseek.com/quick_start/pricing/), usage cost is **USD 0.027169008**; conservative peak accounting is **USD 0.054338016**, below the **USD 0.15** hard ceiling. No invoice or balance delta was queried. Existing server capacity was used.

Preparation and audit were AI-assisted and unblinded; no independent human review is claimed. No GitHub/npm publication or comment posting was performed.

[analysis.json](data/launchgate-structured-model-2026-10-26/analysis.json) · [protocol.md](data/launchgate-structured-model-2026-10-26/protocol.md) · [execution.json](data/launchgate-structured-model-2026-10-26/execution.json) · [output-audit.json](data/launchgate-structured-model-2026-10-26/output-audit.json) · [trajectories.jsonl](data/launchgate-structured-model-2026-10-26/trajectories.jsonl) · [manifest.json](data/launchgate-structured-model-2026-10-26/manifest.json)

<!-- prospective-holdout-followup -->

[Prospective new-fixture results](flow-guard-prospective-holdout-2026-10-26.md): 89/96 natural first proposals valid, five of seven repaired, two withheld; controlled repair 45/48. Separate post-hoc ranking/missing-set facts passed offline checks, without a new model run.
