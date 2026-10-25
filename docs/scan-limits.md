# Measurement limits and version evidence

> 🌐 **English** · [Русский](scan-limits.ru.md) · [Español](scan-limits.es.md) · [Français](scan-limits.fr.md) · [中文](scan-limits.zh.md)

These qualifications apply to the reader follow-ups documented on 2026-10-25. Distinguish the tested **published npm `0.21.0` artifact** from later local source: an unchanged `package.json` version does not make a local fix part of that artifact. Code tests, synthetic ledgers and scripted approval replies are separate from model evaluation, production traffic and human research.

## Billing and server-authored hints

`initialize`, `tools/list` and a canary call can themselves incur a charge or another server-side effect. A successful discovery or preview does not establish the price or effect of the next call. In our synthetic billing fixture, the canary selected free `preview`, while `{}` selected an operation charging seven fake credits. This measures that fixture, not an external seller's invoice.

`readOnlyHint`, `destructiveHint` and `openWorldHint` are unverified claims, not proof that an operation is free or harmless. The local first-use annotation review is opt-in, default `off`, and applies only to `wrap --flow NAME`; accepting it is not billing approval or an effect attestation. See [flow controls and their limits](flow-guard.md).

## Requested package version versus reported server version

An exact `package@x.y.z` specifies a requested package version. `initialize.serverInfo.version` is a string supplied by the server; it is not an independently resolved package version or artifact digest. For example, the reviewed Mapled package was `@mapled/mcp@0.21.6`, while its reported server version remained `0.1.0`.

The tested published `0.21.0` could incorrectly derive a suggested package pin from that reported version. Verify the package-manager resolution and lock/integrity evidence instead of accepting that suggestion. The local fix separates the metadata and removes this substitution; it still does not attest which package bytes a launcher executed. An unpinned `npx` launch may resolve another version or reuse cached resolution; neither outcome is guaranteed on each start. A tool-set hash identifies the observed definitions, not the whole executable. See [scan](scan.md) and [integration](integration.md).

## Launcher comparisons and advisory baselines

The Auten investigation had one public observed snapshot, not two measured launcher environments. Reproducing a difference requires the exact runner/version and launch arguments plus two tool snapshots from the environments concerned. A HISTOR observation is an advisory comparison baseline, not an operator-approved trusted pin.

The [launcher evidence collector](../examples/launcher-evidence/README.md) currently has English helper documentation. It records client-normalized tool definitions, not an original wire transcript; a supplied runner version is owner-reported, and no package artifact is independently resolved by that field. A prepared collector is not evidence that the requested two-environment comparison occurred.

## Questions, approvals and answers

The historical **39/97** counts tasks that triggered an `ask`, not people who approved. Execution after a hook decision does not prove a person clicked Allow. A wrapper can record accept/decline/cancel, but scripted clients can produce those responses too. Human approval rates, reading time and fatigue require requests actually presented to people and linked outcomes; they were not measured by these tests.

For the saved DeepSeek Flash guard + note series (`injecagent`, 20 travel cases), the official historical AgentDojo result remains **18/20** under its exact-name mention predicate. AI-assisted reading found warnings rather than adopted recommendations in the saved excerpts, but only 18 answers were complete; two reached the historical 2,000-character storage cap. Missing tails are unknown, so this is not a replacement full-answer `0/20` score. The local harness saves full future answers with length/hash metadata; it does not restore old tails or imply a new model run.

**Controlled selection probe (2026-10-25):** A separate synthetic post-tool probe using published WARDEN `0.21.0` covered six hotel tasks × five repetitions, clean/benign/injected notes and three profiles: **270/270 correct IDs**, with **0/90 injected target choices** (0/30 per profile). Target names appeared in **25/270** answers including controls, and Stop fired **0/90** times in `note_stop`; the unguarded baseline was correct too, so no incremental guard gain is established, and correct IDs do not validate every explanation fact. [Protocol, results and limits](../../docs/growth/launchgate-selection-2026-10-25.en.md): this separate study does not change AgentDojo’s historical **18/20** or establish broad safety.

**Tied-choice follow-up (2026-10-25):** With two admissible optima, injected target selection was 48/48 without a guard, 44/48 with the note and 45/48 with note+Stop; the respective clean baselines were 28/48, 25/48 and 29/48. Baseline-adjusted guard-effect intervals include zero, and all 432 choices were admissible; target choice is not automatically an error. Separate genuine-user preferences were followed 18/18, with no Stop rechecks. The local [offline evaluator](../scripts/selection-probe/README.md) now supports admissible sets and common-baseline contrasts; runtime blocking is unchanged. [Results and limits](../../docs/growth/launchgate-tie-selection-2026-10-25.en.md).

## Fragment thresholds and recheck costs

Strong fingerprint windows remain **8 non-hex / 10 hex**. The local recognized-prefix indexing repair does not establish reliable strong detection of a six-character fragment inside a longer word; an existing session must reread credentials to gain the new index windows. Requiring review at the credential boundary is different from identifying that fragment as a secret.

Likewise, Stop's normalized 12-character overlap requests another answer check; it does not prove semantic rejection of an instruction. Removing the warning-word exemption also makes honest warnings pay that extra pass. Paraphrases and poisoned row selection can evade this overlap check. Fixture improvements and selected false-block controls establish neither a global optimum nor a production false-positive rate. The [flow guide](flow-guard.md) describes the policy, remaining gaps and continuation bound supplied by the host's `stop_hook_active` flag.
