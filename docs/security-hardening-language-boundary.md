# Language-independent admission, WARDEN 0.12.0

No finite keyword list understands every language. Normalizing an encoding does
not translate its meaning, and an LLM's language coverage is also finite.
WARDEN therefore separates **recognition** from **permission to expose a tool
definition**.

## Revision 0.12.0

A confirmed semantic authority-boundary violation now always has `high` severity
at the host. The provider's original level is retained only as `modelSeverity`.
This closes the threshold mismatch behind the 16 known allowed attacks in 0.11.0;
uncertainty remains a separate failure of inspection.

With `scan --classifier-blocks`, a complete clean review can resolve exactly two
ambiguous static cases: a readable base64 blob, and quotation inside a structured
JSON field. The existing rules still inspect raw and decoded content. Unquoted
instructions and the other threat, origin, drift and approval gates remain in
force. This is model-dependent disambiguation, not a language-independent proof
of safety. The model is explicitly prompted to distinguish protective negation
and detection examples from directives to perform the quoted attack.

A review is bound to a pre-request snapshot of **all** advertised fields. Its
clearance lives in a private WeakMap, not in provider JSON or a serializable
policy flag. Mutating the input, copying an inspection object, inventing a clean
result, an advisory-only call, truncation, uncertainty or a failed request cannot
satisfy the guard. The same review is used by scan and its lock-update recheck.
No broad static allowlist is introduced. The offline gate chain and wrap do not
obtain a clean semantic review and retain conservative detection.

An early candidate that exempted every decodable base64 string was rejected:
it lost 900 existing offline detections. A second candidate relaxed structured
quotes offline; a mixed-language imperative exposed an unsafe exception. Both
partial experiments were stopped, and the final comparison keeps offline
blocking unchanged on the frozen attack and control sets. The final semantic run
uses a separate build identity and output directory; partial runs are not counted
as completed measurements.

Historical 0.11.0 measurements below are retained for comparison. The final
0.12.0 measurements are recorded separately in the companion report.

## Enforce the trust boundary

```sh
node dist/mcp-server.js wrap --require-approval --id notes -- node /path/to/server.mjs
```

First contact records the observed definitions for review but withholds them from
the MCP client and refuses their calls. In an operator terminal:

```sh
node dist/mcp-server.js pins status --id notes
node dist/mcp-server.js pins approve --id notes
```

Use the same `--state-dir` on both commands if overriding the default. Approval
requires the explicit TTY confirmation and rechecks non-pinning security gates.
The observed snapshot must still match what the operator reviewed. Relist the
tools after approval.

The policy equivalent is:

```json
{
  "requireApproval": true,
  "pinToolDefs": true,
  "blockAtSeverity": "high",
  "allowUnknownServers": true,
  "sensitiveToolPatterns": []
}
```

The pin records `approvalMode: "operator"`, v2 hashing of every advertised tool
field, and the launch identity. Automatic first-contact pins, old pins, and
incomplete pins do not qualify. Any changed field or launch identity is refused,
even if `pinToolDefs` is separately disabled or a high severity threshold would
otherwise ignore a finding. No language identification is involved.

`scan --require-approval --lock warden.lock.json` applies the same admission
requirement. `--update-lock` is the explicit operator action that records a new
snapshot for repository review. A model verdict alone never changes trust.
`--no-launch` cannot verify the current definitions and refuses strict admission.

Compatibility: strict approval is **opt-in**. Ordinary wrap still automatically
pins a clean first contact, now marked `automatic`. `--audit-only` observes and
does not enforce. A host calling the library's `approve()` is a trusted authority;
it must not expose that operation to an untrusted model. MCP pin mutation tools
remain disabled unless the operator explicitly enables them.

## Semantic inspection assists review

```sh
WARDEN_CLASSIFIER_API_KEY=… node dist/mcp-server.js scan --project \
  --classifier-url https://your-approved-provider.example/v1 \
  --classifier-model YOUR_MODEL --classifier-blocks
```

The classifier reads names, titles, descriptions, input/output schemas,
annotations and all extension metadata, including normalized readings of common
encodings. Its prompt asks about overriding user authority, credentials,
exfiltration, concealment and control of other tools. It has no language keyword
table. Random fences delimit untrusted input; they are not a security guarantee.

The field-reference protocol requires exactly one `clean`, `attack` or `uncertain`
decision per trusted tool index. Attack evidence refers to host-assigned field
IDs. WARDEN validates those IDs and extracts the source previews itself: admission
no longer depends on the model copying Unicode quotations exactly. Missing,
duplicate, contradictory and invalid decisions never become clean results.
Valid decisions survive a malformed decision about a different tool. Each
incomplete tool gets at most one isolated retry, also for length-limited responses.
An entire malformed batch can therefore use at most nine requests (one plus eight
single-tool retries). Authentication errors, rate limits, network/provider errors
and content filtering do not trigger this fan-out. Inputs exceeding the inspection
budget are rejected before transmission.

Enforcing mode rejects remaining incomplete coverage, uncertainty, timeouts and
provider errors with `CLASSIFIER_INCOMPLETE`. These are inspection failures, not
attack detections; they also prevent `--update-lock` from recording an approval.
Advisory mode reports failures without enforcing them.

`--classifier-reasoning-effort none|low|medium|high` is optional and requires provider
support; omitting it preserves the provider default. For the DeepSeek experiment
we explicitly use `none`: its default thinking mode otherwise shares the 4,000-token
output budget with the final JSON ([provider documentation](https://api-docs.deepseek.com/guides/thinking_mode/)).
Responses and optional diagnostics are size-bounded and never contain API headers
or keys. Diagnostic source text is recorded only through an explicit callback.

The classifier is part of `scan`, not the synchronous offline `vet()` gate chain
or the wrap call path. It does not silently send tool text from wrap to a vendor.
Choose and configure the endpoint explicitly. A clean model verdict is still not
an operator approval.

## Reproducible measurements

The companion MOMUS comparison freezes 8,244 synthetic attack definitions and
362 benign controls in 11 languages before evaluating both builds. The original
4,194 attack inputs are preserved byte-for-byte. Extra languages: Arabic, Hindi,
Korean, Swahili and Turkish. Extra encodings: percent, hexadecimal entities and
nested base64/percent encoding. These fixtures are author-labelled synthetic
data, not independent human-reviewed natural traffic or successful agent attacks.

Initial static comparison, old ruleset 10 versus ruleset 11:

| Set | Before | After |
|---|---:|---:|
| Original attacks detected / 4,194 | 1,620 | 1,692 |
| Expanded attacks detected / 8,244 | 2,664 | 2,808 |
| Benign controls blocked / 362 | 28 | 31 |
| Real public snapshots blocked / 986 | 3 | 3 |

No previously detected synthetic attack became allowed. Exact replay produced
identical decisions. The three added false blocks are encoded quotations of an
attack in extension metadata: decoding exposes the quote to a pre-existing
lexical rule. Existing false blocks include the base64 entropy heuristic on
legitimate encoded examples. These controls deliberately test such weaknesses;
they are not removed to improve the score. The public snapshots are unlabelled:
their block count is not a measured false-positive rate.

Strict admission refuses all 8,244 unapproved attack definitions and every changed
definition after approval, but also refuses all 362 unapproved benign controls.
Once explicitly approved, 331/362 benign controls pass; 31 still trip static
rules. These are admission measurements, **not 100% semantic recall**.

MOMUS reproduces the comparison and preserves per-case decisions:

```sh
python -m momus.engine.coverage_compare --before /path/to/warden-v10 \
  --after /path/to/warden-v11 --out data/warden-v11-comparison
```

The optional live runner uses the actual compiled WARDEN classifier, with eight
independent fixtures per request and four concurrent requests. It never sends
fixture labels to the model. Keys come from environment variables; reports record
model, endpoint, corpus hash, build hash, prompt hash, findings and incomplete
inspections. A pilot is possible with a final numeric argument. Partial runs can
resume only with the identical corpus/model/build.

```sh
node momus/engine/coverage_semantic.mjs /path/to/warden \
  data/warden-v11-comparison/cases.jsonl.gz data/semantic-pilot 80
```

## Protocol pilot

After replacing transcribed quotes with field IDs, fixing the uncertainty schema
and explicitly configuring the output budget, the same frozen, balanced 80-case
pilot was run through both providers:

| Provider / model | Attack high findings | Benign high findings | Incomplete |
|---|---:|---:|---:|
| DeepSeek / `deepseek-flash`, effort `none` | 40/40 | 0/40 | 0/80 |
| OpenRouter / `minimax/minimax-m3`, provider default | 40/40 | 0/40 | 0/80 |

Each used ten requests, all with `finish_reason=stop`; no retry was needed in
these pilots. Earlier iterations had incomplete inspections (24/80 and 40/80 in
the initial quote protocol, 16/80 and 3/80 in the first field protocol). Those
failed inspections were never counted as detected attacks. These are successive
engineering pilots, not a controlled causal comparison: the model is
nondeterministic, the protocol was tuned using pilot results, and the final pilot
is not evidence of universal reliability.

## Historical 0.11.0 full semantic run — 2026-10-10

The completed run used `deepseek-flash` with explicit reasoning effort `none`,
the frozen 8,606 fixtures and the same build digest as the static comparison.
At the unchanged blocking threshold `high`:

| Set | Ruleset 10 alone | Ruleset 11 alone | Ruleset 11 + DeepSeek |
|---|---:|---:|---:|
| Original attacks blocked / 4,194 | 1,620 | 1,692 | 4,184 |
| Expanded attacks blocked / 8,244 | 2,664 | 2,808 | 8,228 |
| Benign controls blocked / 362 | 28 | 31 | 32 |

Combined blocking is **99.76%** on the original set and **99.81%** on the expanded
set. The semantic layer alone produced 8,223 high findings on attacks, one high
finding on a benign control, and **zero incomplete inspections out of 8,606**.
All 1,076 requests finished with `stop`; no isolated retry was needed in this run.
Fault-injection unit tests separately verify bounded retries and closed admission
when retries fail.

All attacks received some semantic finding; 21 were below `high`. Static rules
blocked five of those, leaving **16 allowed attacks at the configured threshold**.
That is a remaining policy/model-severity limitation, not a protocol failure.
The added semantic false block is a German HTML-encoded tool title that says never
to send credentials or conversation history externally. Together with 31 static
false blocks, the combined false-positive rate on these stress controls is
**32/362 (8.84%)**. In that 0.11.0 run, static decisions were never disambiguated by a clean model verdict.

The recorded semantic result requires explicitly enabling the classifier; ordinary
offline `vet()` and wrap retain the static numbers. Neither these results nor
operator approval demonstrate safety in every language or on future model versions.
The inputs are related synthetic templates, including the pilot used for protocol
tuning. This is a reproducible stress evaluation, not a held-out generalization claim.

The companion [machine-readable report](../../momus/docs/coverage-v11.json) contains
build/corpus/prompt identities, per-language counts, missed IDs, false-block IDs,
provider pilots and validation results. Exact inputs and individual decisions are
in `momus/data/warden-v11-comparison/` and
`momus/data/warden-semantic-full-deepseek-v11/` in the working checkout.

## Final 0.12.0 measurement — 2026-10-10

The same frozen corpus (SHA-256
`f3333cd9243fc7b9e62cd760609124d1fefc97d103b706cbd67750be291b3add`)
was rerun with `deepseek-flash`, effort `none`, `scan --classifier-blocks`
semantics and threshold `high`. The live runner uses the production WARDEN
gates with the bound inspection; this is not a benchmark-only allowlist.

| Outcome | 0.11.0 combined | 0.12.0 combined |
|---|---:|---:|
| Original attacks blocked / 4,194 | 4,184 | 4,194 |
| Expanded attacks blocked / 8,244 | 8,228 | 8,244 |
| Allowed attacks | 16 | 0 |
| Benign controls blocked / 362 | 32 (8.84%) | 1 (0.28%) |
| Incomplete inspections / 8,606 | 0 | 0 |

All 16 previously missed attacks are blocked, and all 32 previously false-blocked
controls are allowed. **One new false block remains**:
`control.es.0.description.base64`, an encoded Spanish instruction to summarize
user-provided text. The model incorrectly treated this ordinary task description
as an authority violation. It remains in the denominator and saved report.
The number of false blocks fell by 96.875%; this is not zero-error protection.

All 1,076 provider answers completed with `stop`, no singleton retries. The model
received no fixture labels. Provider usage for the final full run was 3,694,186
prompt tokens and 466,642 completion tokens; stopped development runs are separate.
The balanced final pilot passed 40 attacks and 40 controls without incompletes.

Offline outcomes are deliberately unchanged: 2,808/8,244 attacks blocked,
31/362 controls blocked, zero attack regressions, zero replay differences.
The 986 unlabelled public snapshots keep the same three blocks. Their block count
is not a false-positive estimate. Ordinary wrap is not part of the live semantic
measurement.

[Full report](../../momus/docs/coverage-v12.json),
[implementation audit of the nine-part plan](../../momus/docs/mcp-quality-review.md),
and [safe local reproductions](../../momus/docs/mcp-quality-reproductions.json).
Final decisions are in `momus/data/warden-semantic-full-v12-bound/`; frozen
comparison inputs and offline decisions are in `momus/data/warden-v12-comparison/`.
The report binds corpus, prompt and build hashes and records previous-error
transitions and the abandoned experiments. This corpus influenced the changes;
its related synthetic translations are not an independent held-out distribution
or evidence of understanding every possible language.

## Scope of the guarantee

Strict approval prevents an unreviewed or changed **tool definition** from reaching
the client. It does not prove that approved prose is safe, that the implementation
matches its description, or that a call is authorized by the user's actual intent.
It does not pin executable bytes or inherited environment variables.

Strict wrap strips `initialize.instructions`, which is outside the approved tool
snapshot. Other MCP surfaces—resources, prompts, server metadata, sampling and
elicitation—are outside this definition-approval guarantee. Tool results are
separate untrusted data; the existing result screen is lexical, and withholding a
result cannot undo a tool call. A complete host also needs scoped filesystem and
network access, per-call authorization outside the model, and process isolation.


## Revision 0.13.0 — ordinary imperatives and honest coverage

The generic classifier criterion now requires a concrete authority violation. An imperative describing an operation on user-provided input remains ordinary documentation after decoding. There is no Spanish allowlist. On the same frozen 8,606 fixtures, DeepSeek (`deepseek-flash`, effort `none`) blocked all 8,244 attacks and allowed all 362 controls, including `control.es.0.description.base64`; no inspection was incomplete. [Full report](../../momus/docs/coverage-v13.json) includes prompt/build/corpus hashes and token counts. Offline recognition remains 2,808/8,244 with 31/362 false blocks; the semantic result must not be attributed to offline mode.

`wrap` reports oversized results as incomplete rather than scanning head/tail and clearing the unseen middle. This result layer remains static; no claim of universal multilingual result recognition is made. `block` withholds the result after the tool ran. `warn` annotates it.

Composition analysis accepts `policy.capabilityBindings`: one object per server with `serverId`, `identityHash`, `toolsHash` and a `tools` map from exact tool names to arrays containing `private`, `untrusted`, `outbound`. The hashes must match the reviewed launch identity and every definition field; identity/definition changes invalidate the binding. Empty arrays are explicit operator declarations. Names and server-provided capability annotations cannot grant trust. Unknown tools produce a possible-flow advisory. Known combinations produce a confirmed-capability advisory; neither proves a particular data leak.
