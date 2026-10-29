# Changelog

## 0.22.2 — 2026-10-27

- Reject unknown keys in `server_info` for MCP status and approval calls, matching the existing
  `additionalProperties: false` schema. Calls without `server_info`, empty metadata and partial
  `name`/`version` objects retain their previous behavior. Invalid metadata is rejected before
  an approval is written; reviewed hashes, revision checks and operator opt-in remain required.

<!-- qingfeng-reference-egress -->
## Reference-only egress checks — 2026-10-26

- Add 25 synthetic regressions for reference-only outbound payloads, observed intermediary results, new turns, operator labels, modes and exact one-use grants. Linux build/typecheck and 127 tests in four relevant suites pass. No runtime or threshold changes; no paid model calls.
- Document expected review/deny behavior separately from explicit policy exemptions, unknown non-MCP tools and unobserved credentials. An exact grant does not certify semantic publicness. [Report in five languages](docs/flow-guard-reference-egress.md).
<!-- /qingfeng-reference-egress -->

## 0.22.1 — 2026-10-26

Ships the local source recorded below. npm `0.22.0` did not include it.

- Add an opt-in host-owned structured answer gate and captured-fact repair feedback for numeric ranking and missing eligible sets, as recorded below. Frozen experiment snapshots retain their original 0.22.0 identity; the version bump does not rerun or alter those results.

<!-- final-ranking-witness -->
## Local final ranking-feedback validation — 2026-10-26

The unchanged candidate completed a separate 120-call Linux comparison: old feedback repaired 6/40 known-failure continuations, explicit selected-versus-best feedback repaired 40/40; valid controls remained 20/20 per nominal arm. All delivered frames passed arithmetic audit. This closes the selected-cohort series, not a new holdout. Production repair bounds and local unpublished 0.22.0 are unchanged. [Report](docs/flow-guard-final-witness-2026-10-26.md).
<!-- /final-ranking-witness -->

## Local follow-up — ranking and missing-set counterevidence, 2026-10-26

- After a frozen prospective 24-fixture run, add bounded captured-fact feedback for `not-optimal` and `incomplete-eligible-set`: selected/best numeric values, direction, a safe optimal record reference, counts and at most eight missing eligible references. Never copy source labels, IDs or prose. Schema, validation rules, output decisions and two-correction limit stay unchanged.
- Linux build/typecheck, 798 WARDEN tests (50 gate/stdio) and 28 red-team scenarios pass. Replay of 210 saved proposals/156 trajectories preserves all decisions and final frames; no new model call tests the improved messages.
- Keep frozen live outcomes separate: natural first 89/96, five of seven errors repaired/two withheld; controlled final 45/48/three withheld. Seven second repairs produce two successes/five withholdings. No invalid delivered result in the sample; synthetic supported types and same-author limitations apply. [Five-language report](docs/flow-guard-prospective-holdout-2026-10-26.md). Local 0.22.0 only, not published.

## Local follow-up — host-owned structured answer gate, 2026-10-26

- Add opt-in `createAnswerGate`: host-frozen numeric/boolean rules, safe record/field references, complete eligible-set and optional ranking checks. After every proposal, recheck every admitted alternative against all rules; C-to-D substitution is a new violation, not success.
- Buffer delivery through an explicit host SDK: initial proposal plus at most two corrections, fixed independent notice, and withholding after unresolved/unknown input. One output reservation per instance; no automatic retries after provider, cancellation, timeout or uncertain output failure. An ordinary Stop hook remains a one-continuation request, not a final-display owner.
- Include an actual stdio host example and regressions; arbitrary prose, source truth, native-client GUI rendering and new model repair efficacy are outside this check. Clarify source-record numbering in legacy constraint feedback. Five-language [contract and limits](docs/flow-guard-answer-gate.md). Local 0.22.0 only; no publication.

## Local follow-up — deterministic answer evidence, 2026-10-26

- Add optional host-owned `answer_check` and exported `checkAnswerConstraints`: exact answer/session/turn binding, finite numeric/boolean rules, selected and explicitly eligible items, partial/invalid status and fixed numerical counterevidence. Constraints must originate in real user/operator policy; source data remains conditional, and native hooks do not automatically extract this contract.
- Preserve a guard-owned source-instruction notice after a host-marked Stop continuation without requesting a second recheck. Keep any existing model disclosure in the review instruction. A host must display `systemMessage`; this does not guarantee model-prose preservation or native-client rendering.
- Add a closed-schema synthetic-probe claim adapter and saved-pair replay. Linux build/typecheck, 743 WARDEN tests in 21 files, 24 Python tests and the existing 28-scenario deterministic gate pass. Replay detects all four known eligibility contradictions and emits continuation notices for all twelve saved pairs, including the three prior disclosure losses; it does not regenerate or correct model answers. Verify 276 output hashes and synchronize the Linux-generated local build/plugin. No npm publication, GitHub write or public article change. See [contract, results and limits](docs/flow-guard-constraint-evidence.md), also in RU/ES/FR/ZH.

## 0.22.0 — 2026-10-25

Ships the local source recorded below. npm `0.21.0` did not include it. The entries below describe changes since 0.21.0.

- Add opt-in `annotationReview: "first-use"` for unverified MCP tool annotations. Server hints remain untrusted and never authorize effects or payments; the default remains off.
- Distinguish a requested package version from the version reported by a server when reviewing launch changes.
- Include the credential-window and flow-guard module changes recorded below.
- Add a repository-only selection evaluator with admissible choice sets, matched baseline comparisons and separate selection/mention metrics. The tie experiment does not establish reliable added guard benefit; no new runtime selection-blocking behavior is claimed. The evaluator is outside the npm package file list.
- Expand bounded source instruction signals for role/authority spoofing and add source-warning and Stop-trigger diagnostics. Keep semantic compliance unassessed and the existing overlap/continuation contract; saved-answer hook replay cannot establish changed model behavior. Local candidate only, not published by this change.
- Keep Post/Stop warnings free of raw tool/source metadata and detected-text quotes. Use stable opaque source IDs for correlation only; add hostile identifier/URL regressions and update source-identification tests. This is warning-channel custody, not semantic prevention.
- Record a fresh 720-answer, five-profile model comparison on Linux: injected target choices 48/48 unguarded, 44/48 and 46/48 published, 27/48 in both local candidate profiles; keep different clean baselines and six-cluster intervals visible. Twelve actual Stop continuations change no selected IDs. All 30 genuine-user controls pass; admissible IDs do not prove factual explanations. No independent holdout, native-client or broad security claim; no npm publication. Evidence: `docs/evidence/launchgate-live-comparison-2026-10-25/` in the monorepo.

## Local source — credential-window measurement and prefix indexing, 2026-10-25

- Retain non-hex/hex strong windows at 8/10 after Linux hook comparisons at 6/7/8. Recognized normalized provider prefixes no longer cause alphabetic payload before the first digit to be skipped. Preserve generic/DER starts, every previous fingerprint and the existing storage format; existing sessions need a credential reread to gain new windows.
- Add a reproducible threshold sweep with two synthetic seeds, corpus manifests, whole-call decisions and deliberately selected collision controls. At unchanged 8/10, 717 of 14,400 attack fixtures change from ask to deny; all attacks already required ask or deny. Decisions on 7,680 benign requests per profile remain unchanged. A broader generic-prefix candidate was rejected for a false hard denial. These are fixture results, not a production false-positive estimate. [Study and evidence](https://github.com/alexar76/aicom/blob/main/docs/growth/warden-thresholds-2026-10-25.ru.md). Local only, unreleased.

## Local source — flow guard split into modules, 2026-10-24

- `src/flow-guard.ts` (2,286 lines) is now the public API and the hook entry point. The code moved unchanged into `src/flow-guard-*.ts`: types, paths, policy, text, classify, screen, destinations, fingerprints, decode, fragments, leak, state, pre, post, answer and labels. Exports and behaviour are the same: the existing tests pass unchanged, and the code-aware red team writes the same report as before (0 of 28 delivered).
- The Claude Code plugin carries `scripts/flow-guard.mjs` and its `flow-guard-*.mjs` parts. `npm run build` writes them; a test checks every copy against its compiled file and refuses any import other than node: built-ins and the guard's own parts. The parts sit in `dist/` beside the other modules, so the MOMUS release gate's build digest (`dist/*.js`) still covers the whole guard. Replaying another build with `WARDEN_FLOW_GUARD` needs the parts in the same folder.

## 0.21.0 — 2026-10-24

Ships the local source recorded below. npm `0.20.0` did not include it.

## Local source — second native macOS audit, 2026-10-24

- Bind native target opacity through its ancestor chain and refuse fully transparent windows/controls, blocked modality and pending sheets, including logical sheetParent transitions before attachedSheet is populated. Observe sheet/minimize transitions before effects.
- Pin ABI-checked method_getImplementation and invoke that exact IMP directly. NSApp.sendAction overrides can reroute, defer or return success without the approved handler, so they are no longer a dispatch authority. Registered handlers must enforce their own permissions and support direct invocation.
- Recheck the revision after injected clocks and prepare callbacks; allocate the receipt revision before effects and guard monotonic deadline overflow. Add real-window regressions for these paths and preserve strict defaults. Update five languages; no npm publication or remote release gate.

## Local source — follow-up atomic backend audit, 2026-10-24

- Refuse native target changes during overridable hit-test in both prepare and commit by recapturing target state; recheck wall and monotonic expiry immediately before dispatch. Hidden application mutations still require explicit invalidation.
- Reject Objective-C block sender signatures (`@?`) rather than accepting the object prefix. Add real AppKit regressions for stale preparation, handler/title/enabled/frame drift without invalidation, both clocks and reentrant handlers.
- Add a monotonic deadline to the generic TypeScript atomic server, reclaim expired pending capacity with either clock and recheck expiry after target validation. Keep strict mode and local-only scope; update five languages.

## Local source — native target-side macOS backend, 2026-10-23

- Add the local Swift WardenDesktop package, WardenDesktopSurface and bounded exclusive-stdio transport. Compare live registered AppKit button/target/selector/implementation, window/focus, metadata and hit-test on MainActor; recheck revision after overridable hit-test; dispatch directly to the retained target without AX/CGEvent/performClick or responder routing. Validate void target-action signatures, bounds and unique identities; retain targets and consume five-minute wall/monotonic tickets before effects.
- Provide a real native demo window and local build:macos / test:macos commands. This is an application-embedded backend, not an injector for unmodified third-party apps. MainActor model invalidation before mutations and synchronous non-modal handlers are required; receipts attest local dispatch, not external payment/mail completion. Raw effects and unsupported typing/keyboard/clipboard paths refuse. No TCC or global input changes.
- Add a separate real macOS integration gate with production/test binaries, cross-language stamp parity, Unicode, target/handler/object/frame/window drift, ABA, hit-test reentrancy, clock rollback, replay/cancel/restart and actual wrap forms. Compile test endpoints out of production; fail rather than silently skip when native prerequisites are absent. Configure macOS CI jobs locally and update five languages. No remote CI, publication or deployment.

## Local source — atomic screen target CAS, 2026-10-23

- Add opt-in `wrap --screen-atomic`: private prepare/commit/cancel protocol binds a one-use ticket to the full action, target stamp and surface revision. Require enforcement and a supported server; never fall back to raw GUI dispatch. Validate receipts, hide tickets, refuse oversized incomplete previews, preserve uncertainty leases and never retry effects.
- Add exported `@aimarket/warden/atomic-screen` server runtime. A shared server-owned surface compares and synchronously commits to the resolved target in one critical section. Rotate revisions on every mutation/commit, including hidden handler changes and ABA; consume tickets before effects, expire pending capacity and invalidate uncertain state. Reject async callback registration and reentrancy. Other mutation paths and transport authentication remain the backend's responsibility.
- Include a runnable virtual-form server with no OS/network/payment effects. This is not a native desktop adapter: asynchronous OS/browser RPC, cached snapshots or untracked external mutations cannot satisfy the atomic ownership contract. Strict remains default; hooks and snapshot-only mode retain their previous limits.
- Add server and real stdio regressions for the final-read/commit race, same-metadata revisions, exact argument binding, replay, expiry, restart, cancellation, raw-call refusal and malformed/uncertain receipts. Update all five languages. Local only, no publication/deployment.

## Local source — Auten outcome approval and fresh target checks, 2026-10-23

- Add explicit taskAdapter review mode and one-use ordered task_run plans. Show one unchecked MCP outcome form before the first effect with all fixed destinations/bodies; disallow caller-supplied steps and individual task_execute in review mode. Refuse missing form support and non-explicit acceptance.
- Hold a task execution lease across approval/run and atomically reserve the entire plan plus operation budgets after acceptance. Recheck pin/policy, expiry, cancellation and authentication binding before every fixed step; stop the rest on drift/error, preserve spent reservations and never claim rollback of earlier effects. Record approval separately from execution outcomes.
- Add opt-in wrap --screen-read / --screen-read-input for an operator-selected same-server observation schema. Observe before the question and after acceptance, recheck definitions and risk context, and compare the fresh response's target role/reference/accessibility identity/bounds/context. Refuse unsupported/ambiguous schemas, pixels-only results, changed targets, failed reads and cancellation.
- Serialize known GUI effects across enforcing proxies in one flow session; an uncertain missing result leaves a non-reclaimable lease for operator review. Audit unchanged/refused/uncertain screen checks separately from user approval. Hooks cannot revalidate between the client's dialog and execution.
- Strict remains default. Structured plans do not grant arbitrary GUI chains. Snapshot and click remain separate calls; cached/false server metadata, external actors and unchanged event handlers require a trusted atomic server-side revision/effect contract for stronger guarantees. Update all five languages and prepare an unsent Auten reply. No publishing/deployment.

## Local source — Gautam regressions and failing replay gate, 2026-10-23

- Add bounded decimal scalar-code and NATO-word candidates, including explicit numeric arrays and case markers for nested encodings. Unknown items break a run; candidates share existing limits. Decoding alone never denies ordinary numbers/prose. First 1–4 character encodings still require review at the credential boundary.
- Classify unlabelled MCP Git commit/push and GitHub push_files, with common camelCase/dotted names, as outbound/persistent effects. Keep get_commit/list_commits as reads. Add regression fixtures without performing any real commit or push.
- Extend the original 23 end-to-end scenarios with five Gautam cases. `test:redteam` now fails on reopened delivery, missing/duplicate cases or inconsistent outcomes: 26 tool attacks and two answer-only note/recheck cases, never conflated. Fault-injected reports prove the gate exits nonzero.
- Wire the gate into local WARDEN/workspace CI, npm prepublishOnly and registry publication workflow. No remote workflows or publication were triggered. Update all five languages and prepare an unsent response.

## Local source — constrained task capabilities, 2026-10-23

- Keep strict GUI behavior by default and retire automatic permissions based on untrusted snapshots, including legacy `gui.mode: "policy"`. A spoofed Close/role/accessibility ID cannot authorize Send. Geometry/focus/translated labels remain explanation only.
- Add opt-in `warden-mcp task`: a built-in MCP effect adapter with pinned UTF-8 resources and exact operator-reviewed HTTP requests, selected only by fixed IDs. No arbitrary GUI forwarding, browser profile, clipboard, page scripts or dynamic payloads. Bind its MCP name explicitly in protected `taskAdapter` policy and pin the manifest bytes.
- Validate the entire manifest and RPC schema, reject duplicate JSON keys/extra metadata, bound expiry, request/response size and time, deny redirects and retries. Persist per-task budgets before dispatch under a cross-process lock and fsync; restart, uncertain outcomes, cancellation after dispatch or manifest edits cannot replenish a spent task ID. Keep audit free of payloads/tokens.
- Narrow Copy exceptions to exact known keyboard tool names. Regressions cover policy spoofing, first 1–4 secret characters/encodings, exact request bodies, independent server processes, redirects, state corruption and uncertain payment outcomes.
- Rerun deterministic AgentDojo locally without network/model API: intent 0/579 delivered action attacks, 57/97 clean tasks without a question, 58/97 clean completion, 608/949 completion under attack (historically 613/949). This does not measure GUI usability or recertify live-model results. Five-language docs cover setup, migration, payment semantics and limits. Nothing published or deployed.

## Local source — credential boundary and layered encodings, 2026-10-23

- Require review after credentials plus outside text for supported outbound/MCP calls, including read-only labels and one-character/unknown-encoded arguments, and ordinary project-file writes. Keep a sticky credential flag across prompts and bounded source-history rotation. This supersedes the former length-dependent automatic-pass behavior.
- Add optional exact public-request rules to protected user policy. Bind full tool/all canonical JSON arguments; consume each rule once per session under the shared lock. Never waive detected leaks, incomplete scans, saturated stores, GUI controls, shell/destructive actions or protected settings. Reject extra RPC metadata and malformed arguments for automatic grants.
- Compose bounded URL, canonical base64/base64url, UTF-8 hex, Unicode/hex escapes, numeric entities and English character-list candidates. Report depth/variant/text exhaustion explicitly; never interpret it as clean data. Validate corrupt fingerprint files, preserve standalone PII checks, and bound e-mail matching to prevent long non-address payloads from causing quadratic scans.
- Real stdio regressions check tiny/encoded arguments, concurrent once-only public rules, retry/metadata bypass and no delivery without approval. Workflow fixture: 0/16 automatic attacks in both profiles; strict default reviews 12/12 benign calls, exact reviewed rules 0/12. The fingerprint-only corpus reports 0 hard false denials and 2 reviewed files among 758; these are distinct measurements, not a production rate.
- Five-language docs include the same validated policy example, approval semantics, bounded decoding and explicit usability costs. No public rules are installed, and no publishing or deployment occurs.

## Earlier local iteration — first-fragment review, 2026-10-23

- Stop the first matching short credential fragment with per-call `ask` before execution (`deny` refuses). Preserve hard denial for two distinct adjacent six-character pieces. Earlier approval never whitelists a repeated or later call.
- Add narrow five/seven-character and known-prefix-boundary fingerprints, excluding public prefixes and tiny suffixes. Decode short supported URL/base64/character-list candidates and delimit atoms without weakly scanning long uninterrupted hashes.
- Version the hash/offset/size index as v2; old v1 sessions require review and a fresh session/reread for complete tracking. Validate both index and observations; retain conservative capacity and corruption handling. GUI policy cannot waive ambiguous fragment review.
- Regression tests assert no first-fragment server delivery for concurrent unapproved calls and for decline/cancel/missing elicitation. An explicit approval forwards one call only.
- The new-rule 480-key/757-file probe measures 0 hard false denials and 2 files requiring review, not zero false positives. Five-language documentation explains scope, approval semantics and remaining limits. No npm publication, GitHub write or deployment.

## Earlier local iteration — secret-transfer regressions, 2026-10-23

- Correlate distinct adjacent six-character credential payload fragments across fields, turns and concurrent proxies; a single short match, repeated piece, overlap or unrelated key is insufficient. Shared prefixes and DER structure are excluded. Earlier partial disclosure remains possible.
- Decode explicit English character/digit lists with bounded input and reset at unsupported units, then apply existing secret checks. Arbitrary verbal encodings remain outside the decoder.
- Store bounded hash/offset metadata under the session lock; fail conservatively on legacy or exhausted tracking and fail closed on corrupt state. Project-file writes also receive the new correlation check. Strict GUI stays the default; detected secrets cannot be exempted by GUI policy.
- Hook and real concurrent stdio regression tests verify refusal before server delivery. The unchanged 23-case deterministic red-team harness moves from 2 delivered to 0 delivered (two answer-only cases are noted/rechecked). Five-language documentation separates this local result from historical AgentDojo/corpus measurements. No production deploy or npm publication.

## Unreleased

- **Superseded by the constrained task mode above: optional GUI policy mode** (`gui.mode: "policy"`) reduces questions only for explicit exact tool/action/role/accessibility-ID rules scoped to a site origin and/or application ID. Strict behavior remains the default. Validated coordinates and focus resolve the target; visible labels never grant permission. Bounded plain typing and configured navigation keys are supported, with snapshot age and one-use reservations under the session lock. Unknown/malformed policy or call shapes fall back to strict behavior with a diagnostic. Send/pay/delete/submit, Enter, paste, sensitive-data matches and credential reads retain their checks. Forwarded input/paste gates later clicks for the rest of the session. Local stdio tests compare four strict forms with one policy form for the same four fixture calls; this is not a real-world utility measurement. Five language docs include the same validated configuration example.


The local source closes automatic-pass paths for coordinate clicks, pixel-only screens, Enter in a focused field and non-English labels. By default, after untrusted content, every recognized GUI pointer action, text input/fill, paste and non-exempt keyboard action requires approval (`screen_action`; `deny` refuses). Target labels and element-list formats no longer decide whether approval is required. English target words only improve the explanation. A user-named or policy-allowed destination does not exempt GUI actions.

- Only exact copy/select-all chords in a strict known schema are exempt from the GUI rule; extra fields, sequences, malformed arrays, trailing newlines and oversized values ask. Visible-secret checks remain in force. Unknown/missing generic controller actions ask; exact known observation actions with only `action` are exempt. CamelCase and dotted/hyphenated names are normalized.
- Coordinate hit-testing against unambiguous JSON boxes or exact centers, reported focus/form relations for Enter and cmd/ctrl+Enter, semantic submit types, accessibility/automation ID hints and a small multilingual action vocabulary improve the approval explanation. Overlaps, conflicting geometry, invalid values and conflicting duplicate nodes do not resolve a target. These are explicitly untrusted snapshot hints; context alone never exempts an action, while explicitly configured operator rules can permit reviewed interactions. Raw accessibility identifiers are not retained in element metadata or shown in the prompt. Asking only after paste/input remains insufficient for prefilled messages, payments and deletion.
- Clipboard paste asks without needing a recognized credential read; the more specific `paste_after_secret` reason remains when such a read was recorded. Plain typing and Enter ask even without a visible credential or focus description.
- The previous large-image text-budget and stale-screen fixes remain: binary image/audio result data does not hide later text, action results refresh the screen map, acknowledgments retain it and image-only results clear it. Outgoing arguments keep all secret checks.
- Hook and real stdio-proxy integration tests cover coordinates, pixels, multilingual labels, Enter, unknown schemas and per-action approval, asserting refused calls never reach the server. Five language documents explain the behavior and limitations.
- This deliberately increases confirmation frequency, including benign navigation and message-body clicks. No OCR or visual instruction classifier was added; answer-only pixel injection, arbitrary renamed tools and hidden server behavior remain outside this rule. It requires recorded untrusted content, enabled enforcement and a client that honors hook decisions. See [the flow guard documentation](docs/flow-guard.md#opaque-gui-actions-local-source-2026-10-23).

npm `0.20.0` did not include the screen-control fixes. They ship in 0.21.0.

## 0.20.0 — 2026-10-22

What 0.19.0 still let through, closed as far as it goes without false positives, and one false positive of 0.19.0 itself. [The flow guard doc](docs/flow-guard.md#what-changed-on-2026-10-22-and-why) has the table; 2 of 23 code-aware attacks still get through, both named.

- **Fixed in 0.19.0's key windows:** after a session read an RSA private key, sending a README that holds a DKIM public key was denied as "part of a credential": every DER key shares its algorithm identifier. Parts every key of a kind shares (DER headers and algorithm identifiers, a JWT's header and claims) are no longer fingerprinted. Measured with `scripts/redteam/window-collisions.mjs`: 480 made-up keys in eight formats against 115 million letters and digits of ordinary text (this monorepo and 1,000 HISTOR packages); 0.19.0's rules matched by chance 19 times, these match 0 times.
- **Smaller key windows where that measurement allows:** 8 letters and digits (10 for hex keys, which share their alphabet with every hash and address); pieces of 8 characters wrapped in other words are now denied. Base64 is decoded from 12 characters.
- **A key read this session written into an ordinary project file asks** after outside text; `.env` and the other credential files still pass.
- **An address only in pasted or quoted text is not one the user named** (`<pasted_content>` blocks, `>` lines, message headers, forwarded messages): sending to it asks once. A full stop or comma after a typed address no longer makes it unnamed.
- **The Stop hook sends an answer back once** when it repeats the sentence in which outside text addressed the model, skipping sentences that report the attempt. Measured on AgentDojo's answer-only task (travel, injecagent, 20 user tasks): on Ministral 8B via OpenRouter, which follows the attack (6 of 20 answers recommend the attacker's hotel without the guard), the guard's existing note already took that to 0, and the re-check fired 3 times without changing an outcome; on DeepSeek V4.1 Flash it fired 2 times in 20. Two narrowings came from those runs: the instruction is its own sentence only (in a quoted review list it ran on into the next reviews), and sentences that warn about the attempt are skipped (DeepSeek quoted the hotel in 19 of 20 warnings).
- **Ruleset v16:** two `TOOL_DEF_CROSS_TOOL` patterns for tools that take no input, from MCPTox's dev half. Held-out half 194 → 210 of 218; 0 of 45 clean servers; the field corpus and a 1,000-package HISTOR sample block exactly what v15 blocked. Five false positives of a first draft are pinned as tests.
- **`wrap` enforces `sensitiveToolPatterns`.** Until now `wrap` accepted the patterns in `--policy` and passed matching calls straight to the server, although the policy type says they "always require explicit user approval" (an outside review of 2026-10-22 found it; no test covered it). Each call to a matching tool now waits for a person: `wrap` asks through the client's MCP elicitation form, with the tool, server and arguments, and only a ticked, accepted answer sends that one call. The box starts unticked, so a client that accepts forms with their defaults approves nothing. A client without a form gets a refusal (`--ask refuse` refuses without asking); a call the client cancels while the person decides, or whose definitions change meanwhile, is not sent. With `--flow`, a send the flow guard would ask about is asked the same way instead of refused, and the answer is logged as `approvalOutcome`. 7 tests; 6 of them fail on the previous `wrap`.
- **Measured:** the AgentDojo replay gives the same 1,046 records as 0.19.0. The model harness gains `--guard-stop`, `--injection-tasks`, `--obedient-any` and the final answer in every record; `relay.py` sends DeepSeek's `thinking` switch only to DeepSeek, and `run-model.sh` takes `RELAY_EXTRA` for another OpenAI-compatible endpoint.

## 0.19.0 — 2026-10-22

What the flow guard and the rules still missed, closed where it could be, and measured. A reader asked what WARDEN still does not catch; [the flow guard doc](docs/flow-guard.md#what-changed-on-2026-10-22-and-why) has the list and what is still delivered.

- **Keys sent in pieces or disguised.** Key-like values (random-looking runs in credential files, well-known token formats anywhere) are also fingerprinted in 10-character windows of their letters and digits, read forwards and backwards, with Cyrillic and Greek look-alike letters folded; base64 is decoded from 16 characters, not 24. Each argument keeps the tail of what it sent after outside text, so pieces sent back to back through one argument are checked whole, including card and account numbers. A key's leading format (`rk_live_`) never counts as a piece of it.
- **Unlabeled MCP tools that reach a party are outbound**: an argument such as `to`, `email`, `attendees`, `assignee`, `collaborator` or `username`, or any e-mail address or IBAN. `warden-mcp flow-labels` lists the unlabeled tools sessions used, with the guard's guess and a `labels` block to correct.
- **Stop hook** (`warden-mcp hook stop`, registered by the plugin): one line under an answer whose turn read outside text, naming the sources, and saying so when any of it addressed the assistant with instructions. Never blocks; policy `answerNote`: `always` (default), `instruction`, `off`.
- **Ruleset v15** widens `TOOL_DEF_CROSS_TOOL` from MCPTox's dev half: the user's call, a passive call, every call, rewrites a mandate binds to a parameter or quoted value, and a call ordered at a fixed target under a threat. Held-out half 171 → 194 of 218; 0 of 45 clean servers; the field corpus and a 1,000-package HISTOR sample block exactly what v14 blocked.
- **Measured:** the AgentDojo replay re-run on the current code (0 of 579 attack actions, 57 of 97 tasks with no question, 608 of 949 done under attack; the changes above alter no decision, so the drop from 58 and 627 is the 2026-10-18 audit fixes); 17 code-aware attacks in `scripts/redteam/flow-redteam.mjs`, 14 delivered before and 3 after. `scripts/agentdojo/Dockerfile.dockerignore` makes the documented reproduce command build again; `summarize_oracle.py --ran-in` records where a run happened.

## 0.18.0 — 2026-10-21

Re-approval shows what changed, field by field.

- **`pins status|approve|revoke` and `status_mcp_server` show a field-level diff** before the full definitions: every changed value with its path, the words added `{+…+}` and removed `[-…-]` inside descriptions, schema values `before → after`, which entries of a list such as `required` or `enum` came and went, and which tools were added or removed. A change made only of digits, separators or whitespace (a live counter, a date, a limit) is marked "numbers only" and still needs approval: a number can be a limit. `status_mcp_server` returns it as `changes` (structured) and `reviewText` (escaped lines); the library exports `diffToolDefinitions`, `formatDefinitionDiff` and `wordDiff`.
- Why: in HISTOR's snapshot of 2026-10-20 (23,821 recorded changes over four weeks), 59.5% changed a tool's description (45.1% by more than digits and whitespace) and 30.8% added or removed tools, while 13.4% changed nothing but digits, separators or whitespace. Two full JSON blobs per change made those look alike. (This entry first said 52% and 23%; a recount of `changes.jsonl.gz` could not reproduce either. The counting script is in [the release post](https://modelmarket.dev/blog/mcp-servers-edit-the-instructions-your-agent-reads-warden-018-shows-which-words-changed/).) The pin itself is unchanged: any change still needs a human, as before.
- Long rewrites fall back to "common start and end, middle replaced" instead of a quadratic word diff; a review lists at most 200 changed values per tool and then points to the full definitions.

## 0.17.0 — 2026-10-18

### Approval explanations (2026-10-18; local tests only)

- Approval reasons now identify the proposed tool and bounded destination arguments, including channel names and nested recipients. Sensitive targets are redacted; URL credentials, paths and queries, message bodies and shell programs are not included in the preview. Unrecognized target text is omitted.
- Fingerprint matches no longer cite the most recently read files as if they were the matching source. The prompt explicitly says that the source was not retained; destination provenance remains untracked. Outside-text context names the tools whose results were read.
- Decision logs include a stable reason and distinguish `approval_requested`, `refused` and `audit_only`, including `wrap --flow`. `approvalOutcome` remains `unknown`: neither an emitted request nor a subsequent tool result proves a human approved. These changes do not relax decisions or establish reduced approval fatigue. No new model or corpus measurements.

### Security audit follow-up (2026-10-18; no new benchmark runs)

- Gate opaque shell code even for named/allowed destinations; protect expanded and symlinked policy paths and Git hooks/config; reject recognized credential-file uploads.
- Parse URL authority, check all destinations and real target arguments, and match complete user-typed values. Body links no longer authorize unrelated recipients.
- Resolve contacts only through explicit `contactTools`, structured name/email records and unambiguous full names; discard implicit contact authority from older state.
- Record MCP JSON-RPC and tool errors as outside text; withhold responses when tracking fails, and deny pre-tool checks on corrupt state.
- Static ruleset v14 narrows `keyStaysLocal`: remote storage is not local custody. This changes the ruleset identity without claiming new corpus or MCPTox measurements.
- Pin Auten's follow-up with paired synthetic tool fixtures: a saved login name remains allowed, while a signing key supplied by value remains blocked even with the same local-use assurance. Cover advisory thresholds, both tools on one server, and a separate private-key request. No scanner rule changes or new benchmark runs.
- Existing AgentDojo results and policy artifacts remain unchanged and describe pre-audit builds. Only local regression tests validate this follow-up.


The Claude Code plugin adds a flow guard at tool-call boundaries. The entries and measurements below describe its initial, pre-audit implementation.

- **Flow guard** (`src/flow-guard.ts`, plugin hooks `PreToolUse`, `PostToolUse`, `UserPromptSubmit`; CLI `warden-mcp hook pre-tool-use|post-tool-use|user-prompt-submit`). It keeps per-session state of outside text (web fetches, network commands, MCP results, foreign files, files with injection phrasing, MCP servers the session-start scan blocked or could not check) and of private data, fingerprinted on three levels: secrets, personal numbers (card, passport, account, phone) and ordinary private text. After outside text, a call that sends data out or acts for you to a destination you did not name asks; a secret leaving is denied, whatever its encoding (URL, base64, hex); a personal number you did not type asks even to a destination you named; changes to WARDEN's policy or Claude Code's hook and MCP settings are denied. A destination you named is one in what you typed this session. Modes `ask` (default), `deny`, `audit`, `off`; a user-level policy (`~/.local/state/warden/flow-policy.json`) with operator labels, trusted sources, allowed destinations and destination arguments. The plugin runs a byte-identical copy of the compiled module, checked by a test.
- **Measured on AgentDojo** (`scripts/agentdojo/`, `docs/flow-guard*.md` in five languages): replaying a model that obeys every injection, with AgentDojo's own attack and checks, in gVisor without network. Without the guard 593 of 609 delivered attack actions succeed; with it 0 of 584. 57 of 97 user tasks run without a question; under attack 613 of 949 finish (579 without the guard).
- **Measured with a real model** (`scripts/agentdojo/model.py`, `relay.py`, `run-model.sh`, `summarize_model.py`): DeepSeek V4.1 Flash in AgentDojo's own agent loop, every task and pair without and with the guard, eight attack setups in two rounds (21,654 runs, $12.68). Four of AgentDojo's six attacks moved the model to none of 929 attack actions even without the guard (removing the attack's names changed nothing); `direct` ("TODO: …") got through 6 times and `injecagent` once; with the guard every attack run with it stayed at 0 of 929, the guard refusing calls at the attacker in 6 to 11 pairs per attack. Told that the injected message is the user's own, the model carried out 42 attack actions without the guard and 0 with it. With the guard it finishes 51 of 97 clean tasks (90 without), 60 with no question. The container has no network: a host-side relay holds the key, forwards only the conversation and enforces a spending cap; `--guard-note` feeds the guard's PostToolUse note back as Claude Code does, and with it the hijacked model tried calls at the attacker in 9 pairs instead of 49.
- **Two AgentDojo labels were too strict** and are fixed (found by the model run): `share_file` listed the file as a destination, so sharing with an address the user typed asked; `reschedule_calendar_event` listed the event, though moving it reaches only its participants. `summarize_oracle.py` rebuilds the oracle summary from the per-pair results.
- **A person you named by name counts as named** once the session finds their address in your own data: "invite Sarah Baker" followed by a contacts lookup makes the address in Sarah Baker's record yours. It must come from a result that is private and not outside text, and the record must carry a name you typed; a domain read out of that address is covered only together with it. On AgentDojo the replay now runs 58 of 97 tasks with no question (57) and finishes 627 of 949 under attack (613), still 0 of 584 attack actions through; DeepSeek with the guard runs 60 of 97 with no question (57) and finishes 557 of 949 under attack (529), still 0 of 929.
- **A stronger note for instruction-like outside text.** A result that reads like an instruction ("ignore previous instructions", `<important>`) now tells the model plainly not to follow or repeat it. It is the only lever a tool-call guard has against an injection that only changes the answer; on DeepSeek it made no measurable difference (12 vs 12 of 20 for "say this hotel is the best"), and AgentDojo's own attack texts mostly avoid the phrases it recognises.
- **`warden-mcp wrap --flow NAME`: the flow guard for any MCP client.** The proxy runs every `tools/call` through the same guard as `mcp__NAME__tool` and records every result as outside text or private data. All servers a client wraps share one session (the client's process by default, `WARDEN_FLOW_SESSION` to set it), so outside text read through one server stops a send through another. A call the guard would ask about is refused with its reason, since MCP gives the proxy no way to ask; `--audit-only` logs instead. It cannot see the user's prompt or the client's built-in tools.
- **Ruleset v13** (`sha256-jJ3QhJNxLZKAHEp9JKVgmP8H/yXlpMLWNXY0glXQ7Bw=`, 36 rules, 25 block / 11 advise, 24 cover the name, 25 carry a guard). Suggested by a reader of the scanner comparison: the argument's own description is where a tool that takes a key differs from one that uses a stored key. A new `TOOL_DEF_SECRET_REQUEST` rule reads argument descriptions for key material asked for by value in words the older rules do not spell (a signing or wallet key, a key pair, a recovery or secret phrase); it only adds findings, and its guard `keyReference` leaves a reference to a key alone (id, name, path, public half, an argument named `*_name`/`*_id`, a key the tool creates, a key as the unit of a count). It skips tool descriptions, where the same words blocked six honest servers. Writing it found a hole every ruleset had since v4 (2026-08-24): `identifierFragment` read the full stop in "Send me your private key." as part of an identifier, so the sentence passed while the same words without the period blocked; v13 reads an edge dot or hyphen as punctuation, and the guard `keyStaysLocal` leaves alone a key that signs or that the user keeps unless something moves it. On the committed corpus v13 blocks 4 servers (v12: 3, none lost; the new one takes a new mint key pair's 64-byte secret key as an argument); on MCPTox it changes nothing (171 of 218 held-out, 0 of 45 clean, reproduced exactly). Tests: `test/ruleset-v13.test.ts`.
- **`status_mcp_server`, `approve_mcp_server` and `revoke_mcp_server` each describe themselves.** The three were generated from one template, so their descriptions were nearly identical and each one explained what `status_mcp_server` returns (Glama scored `status_mcp_server` 3.8/5 for it). Each now says what it does, when an operator calls it and which sibling to use instead, where it reads or writes, and that the two writes need `WARDEN_ALLOW_PIN_CHANGES=1`. Their output schemas now list every field (they were an untyped object), and `previous_pin_revision` says where its value comes from. `static_scan_tools` no longer calls the 35-rule table a 25-rule one. `lhm.plugin.json` carries the current definitions.

## 0.16.0 — 2026-10-14

For a server's publisher: declare the tool sets your server lists where HISTOR's sandbox cannot see them, in a file on your own domain that changes with every runner release.

- **`warden-mcp declare`.** On a machine that gets the set, `declare --when "runner 1.4, macOS" --out mcp-tool-sets.json -- <command>` starts the server the way a client would, digests its `tools/list` (MTL/1) and adds the set to a declaration file — created if missing, other sets kept, the same digest replaced, at most 64. `--url` reads a remote server instead. `--server-json [--link URL]` prints the `_meta` block for the registry entry (sets inline, at most 8, and/or the file's address). `--check URL --name SERVER` reads a published file the way HISTOR will: the domain the registry verified for the server's namespace (or a subdomain; `<user>.github.io` and the account's raw files for `io.github.<user>`), https on the default port, no redirects, at most 64 KiB; `--check FILE` checks a local file. The rules are HISTOR's: `test/fixtures/declaration-vectors.json`, produced by HISTOR's own implementation, holds the URL, file and condition cases both must answer alike.
- **`HISTOR_DECLARED_TOOLSET` says where the declaration is**: in the registry entry, or in the declaration file it points at (with its address). `HistorCheck.declared` and `HistorSummary.declared` carry `source` and `url`.

## 0.15.0 — 2026-10-14

`scan --histor` tells a tool set that depends on the machine from one nobody has seen, and reports a set the publisher declares in its registry entry as the publisher's word.

- **`HISTOR_UNSEEN_TOOLSET` for a package names local state as a cause.** A package's tools can depend on the machine: a launcher that hands stdio to a locally installed program lists that program's tools there, and only an "install me" tool in HISTOR's sandbox, which does not have the program; a real key can unlock tools a placeholder does not. The finding said the only causes were a version HISTOR had not reached or a package that is not the published one, which reads as tampering to someone whose runner is installed. It now gives that cause first, and the tool count on both sides (`3 tools, sha256-… (latest it ran: 0.1.4, 1 tool in its sandbox)`). Still advisory, still medium. Docs: the five `scan` guides, which also lose a phrase that was written twice.
- **`HISTOR_DECLARED_TOOLSET` (low, advisory): a set the publisher declares.** A publisher can name the tool sets its server lists under conditions HISTOR does not have, by MTL/1 digest, in the `server.json` it publishes to the official MCP registry (`_meta` → `io.modelcontextprotocol.registry/publisher-provided` → `dev.modelmarket.histor/tool-sets`; [HISTOR API guide](https://github.com/alexar76/histor/blob/main/docs/api.md#declaring-tool-sets-publishers)). When HISTOR's `/check` answer carries `declared` for the very digest this machine got, WARDEN reports it as the publisher's word, with its version, date and condition, instead of `HISTOR_UNSEEN_TOOLSET`; info when HISTOR holds no set of its own (`not-observed`). A declaration of another digest changes nothing. The digest a publisher needs is `mtlDigest` in `scan --json`. `HistorCheck.declared` and `HistorSummary.declared` are typed.

## 0.14.0 — 2026-10-11

`scan --histor` says why a package did not start in HISTOR's sandbox, and under which conditions every package finding was made.

- `HISTOR_PACKAGE_SDK_INCOMPATIBLE` (medium, advisory): the version crashes on import for anyone installing it today — written for MCP SDK 1.x (`mcp.server.fastmcp`) with an unpinned `mcp` that now resolves to 2.x. When HISTOR also ran it with `mcp<2`, the finding says how many tools it listed then, and that run's sandbox behaviour is reported as `… (with mcp<2)`.
- `HISTOR_PACKAGE_NEEDS_CONFIG` (info, advisory): the package exited asking for a named key or setting, or its tools were read with placeholders for them.
- `HISTOR_PACKAGE_KEY_SENT_TO` (low, advisory): where the package sent the placeholder key HISTOR set — check that it is the service's own API.
- Every sandbox finding names the conditions it comes from: Linux under gVisor, no internet, decoy secrets ([histor.modelmarket.dev/#conditions](https://histor.modelmarket.dev/#conditions)).
- `HistorCheck.target.packageSignals` types `exit`, `supplied`, `conditions` and `legacy`.
- **The semantic classifier reads a schema value by value.** It sent `inputSchema` (and every other structured member) as one string cut at 2,000 characters, so the end of a large schema was never inspected and `--classifier-blocks` called the tool incomplete. Of 251,413 real tools HISTOR has observed, 6,424 on 2,270 of 16,621 servers (13.7%) hit that cut. Each value now has its own field keyed by its path (`inputSchema.properties.note.description`, property names included) and up to 4,000 characters; a tool may use 32,000 characters and 600 fields in all (99.95% of those tools fit), and requests are packed by volume as well as count. A tool past the budget is still incomplete, never clean.

## 0.13.0 — 2026-10-10

- Semantic inspection distinguishes an ordinary imperative over user-provided input from an attempt to override assistant authority, including encoded text in any language. The frozen DeepSeek run blocks 8,244/8,244 synthetic attacks with 0/362 false blocks and no incomplete cases; these are corpus-specific measurements, not a universal guarantee.
- Oversized tool results explicitly report `RESULT_INSPECTION_INCOMPLETE`; `--results block` withholds them and `warn` marks them uninspected.
- Composition analysis uses operator capabilities bound to server identity and complete tool definitions. Unbound capabilities remain unknown regardless of identifier language. Blocked servers/tools do not contribute an executable flow.

## 0.12.0 — unreleased

- Confirmed semantic attacks always have host-enforced `high` severity; provider severity is retained as `modelSeverity` for diagnostics. Ambiguity remains an incomplete inspection, not a low-severity attack that can pass the configured threshold.
- Complete clean semantic inspections may resolve two narrow static ambiguities: readable base64 blobs and actual quotations inside structured JSON strings. The review is held in private process state and bound to the entire pre-request tool snapshot. Advisory, failed, forged, copied or stale reviews cannot grant these exceptions. Other content rules, threat/origin gates and explicit approval still apply. Ordinary offline vet/wrap remain conservative.
- `scan --classifier-blocks` and lock updates use the same bound review and full WARDEN gate chain. The prompt distinguishes protective negation and quoted detection examples across languages. No new language dictionary or fixture-name allowlist is used.
- New regression tests cover mixed-language execution of quoted instructions, input mutation while awaiting a model, invalid/copy-pasted reviews, strict approval and real CLI lock updates. MOMUS evaluates the production review-aware gates, retaining separate offline, semantic, incomplete and combined outcomes. See `docs/security-hardening-language-boundary.md` for measured results and limits.

- Frozen-corpus result with DeepSeek at `high`: 8,244/8,244 attacks blocked, 1/362 benign false block (0.28%, down from 8.84%), zero incomplete inspections. All old 16 misses and 32 false blocks corrected; one new model false positive remains. No offline attack regression. These are synthetic development fixtures, not universal-language accuracy.

## 0.11.0 — unreleased

- `wrap --require-approval` / `policy.requireApproval` require an explicit operator pin covering every advertised field and the launch identity. Automatic and legacy pins cannot satisfy it; changes fail closed even with ordinary pinning disabled. Unpinned definitions cannot reach `tools/list` or execute a call. Strict wrap strips unpinned `initialize.instructions`; scan refuses incomplete launch-only approval checks.
- Ruleset v11 adds bounded, non-executing decoding of literal Unicode/hex escapes, HTML entities, percent encoding and UTF-8 base64 before the existing rules. Original bytes remain a separate scan and determine the pin. No per-language dictionary added.
- Semantic classification covers all extension fields, adds `cross_tool`, and uses eight-tool batches. Malformed output is an error. `--classifier-blocks` requires full coverage, no uncertainty/truncation and host-validated evidence field IDs. Source previews come from the input, not model-transcribed quotes. Incomplete decisions and length-limited replies retry each affected tool once; provider outages do not fan out. `--classifier-reasoning-effort` configures the provider budget explicitly. Remaining failures block admission and lock updates. Per-tool allow/block lists now agree with the classifier.
- MOMUS expands the frozen stress corpus to 8,244 attacks in 11 languages and 362 benign controls, with separate detection/admission metrics and old-build comparison. Results and limitations: `docs/security-hardening-language-boundary.md`.

## 0.10.0 — unreleased

`--histor` covers stdio servers started from npm and PyPI.

- **Packages, not only endpoints.** For a stdio server launched with `npx`, `bunx`, `npm exec`, `pnpm dlx`, `yarn dlx`, `bun x`, `uvx`, `uv tool run` or `pipx run`, `scan --histor` names the package — `npm:<name>` or `pypi:<PEP 503 name>`, never the version — and sends it with the MTL/1 digest. HISTOR installs each published version of registry packages in a gVisor sandbox (no network, no secrets, no tool called) and records their tool sets, so the answer says whether you run what everyone who installs that package gets. `HISTOR_OLDER_TOOLSET` now reads "you run an older version of this package" and names the version HISTOR last observed; `HISTOR_UNSEEN_TOOLSET` says a version HISTOR has not reached, or a package that is not the published one. Both stay advisory.
- **What stays on the machine:** a local path, a git, GitHub or tarball spec, a private registry (`--registry`, `--index-url`, `--extra-index-url`, `--find-links`), and a plain `node` / `python` / `docker` launch. The report says why nothing was sent.
- `historPackage(command, args)` is exported next to `historEndpoint(url)`.
- **Package findings from HISTOR** (advisory): `HISTOR_PACKAGE_LOOKALIKE` — the package's name imitates a popular one (one character away, the same name under another scope, other separators; the original downloaded 100× more); `HISTOR_PACKAGE_PROVENANCE_LOST`, `HISTOR_PACKAGE_INSTALL_SCRIPTS`, `HISTOR_PACKAGE_PUBLISHER_CHANGED`, `HISTOR_PACKAGE_NEW_DEPENDENCIES` — the marks of a stolen publishing token on the version HISTOR observed. `packageFindings(answer)` exported.
- **What the package did in HISTOR's sandbox** (advisory): `HISTOR_PACKAGE_READS_SECRETS` and `HISTOR_PACKAGE_PERSISTENCE` (high), `HISTOR_PACKAGE_STARTUP_NETWORK` and `HISTOR_PACKAGE_INSTALL_BEHAVIOUR` (medium), `HISTOR_PACKAGE_STARTS_PROGRAMS` (low), from gVisor's trace of the install scripts, the startup and canary tool calls, with decoy credentials in HOME. A `.env` load and a tool's call to its own API are not findings. `behaviourFindings()` exported.
- **Follow changes**: with `--histor` the report links a HISTOR feed of changes to the scanned servers HISTOR knows (`historWatch` in `--json`, a line in the table and the Markdown summary); the scan guide shows the scheduled Action that fails on `TOOL_DEF_DRIFT`.
- **Toxic flows** (`scan`): per client, a tool that reads private data, one that lets outside text in and one that can send data out — Simon Willison's lethal trifecta — reported as one advisory line naming the tools (`flows` in `--json`, a line in the Markdown summary). Capabilities come from tool and parameter names (`read_file`, `send_email`, `url`, `to`), never from descriptions. Never blocks, never changes the exit code. `src/toxic-flow.ts`, `test/toxic-flow.test.ts` (real tool names from filesystem, fetch, github, gmail, slack, memory, context7, playwright).
- **Tool results are screened** (`wrap --results warn|block|off`, default `warn`): the text a `tools/call` result puts in front of the model (text, embedded resource text, structured content; 256 KiB head plus a 16 KiB tail) is read by the static rules. A result a blocking-tier rule fires on is passed with a first text block telling the model it is data from the tool's source, not instructions (`warn`), or withheld with an error saying the tool already ran (`block`); the finding goes to stderr and `--verdict-log`. A clean result is still forwarded byte for byte; `--audit-only` records and changes nothing. `src/result-screen.ts`; five tests in `test/wrap.test.ts`.

## 0.9.0 — 2026-10-09

`scan`: vet the servers your MCP clients start, without changing how they start; ruleset v10; and an opt-in classifier.

- **Ruleset v10** (`sha256-lJuKKKV5mtruN5D+K3X1OK89u6KLXF//oS1NpmhZRuI=`, 35 rules, 24 block / 11 advise, 24 cover the name). New code `TOOL_DEF_CROSS_TOOL`: one tool's text binding to ANOTHER tool's call to rewrite its input ("when using `X`, append …", "any query to `X` must …") or to pre-empt it with a third call ("before running `X`, you must first call `Y` …"), and a tool that takes no input and only orders another call. The anchor is the other tool's identifier; the tool's own name and parameters never count, and naming a tool as the means ("use `X` to change an address", "call `X` first, then this tool") is left alone. Plus `TOOL_DEF_INJECTION` for a definition claiming priority over the user. Guards now receive the tool, so a rule can ask whether a named identifier is the tool's own. Written from half of MCPTox's servers (Wang et al., AAAI 2026) and reported on the other half: v10 blocks 171 of the 218 held-out poisoned tools (0.8.2: 26), none of the 45 clean MCPTox servers, and the same 3 corpus servers as v8. Tests: `test/ruleset-v10.test.ts` (attacks from the dev half, honest corpus sentences early drafts blocked).
- **Opt-in classifier** (`--classifier-url`, `--classifier-model`, `--classifier-blocks`; key from `WARDEN_CLASSIFIER_API_KEY`; also in the Action and, through `WARDEN_CLASSIFIER_*`, the agent-host hooks). Any OpenAI-compatible endpoint, local or hosted. Same prompt, categories and answer format as the HISTOR log's classifier; the tool text is fenced by a per-request random marker and the model's answer is validated as untrusted. Advisory unless `--classifier-blocks`; a classifier that does not answer is reported and never blocks. `--histor` also surfaces the log's stored classifier verdict on the tool set you were served (`HISTOR_CLASSIFIER`, advisory).

- **Ruleset v9** (intermediate, never published; 32 rules, 21 block / 11 advise, 23 cover the name). Six blocking rules from a comparison with two other scanners on attack sets: a phrase or a mailbox in "send … to <address>" (the object must name the user's data; RFC 2606 placeholder hosts and refusals are left alone); `bcc <mailbox>`; the conversation itself sent out, only when the same clause moves it and an outside address, a credential or a concealment cue goes with it; concealment whose target is the tool's own behaviour ("do not tell the user about this / that this tool", "do not mention that you"); a recursive delete of `~` or `/`. The harvest rule's window now crosses the dots of a path (`read ~/.aws/credentials`) and names `~/.kube/config`, `application_default_credentials`, `.docker/config.json`, `.git-credentials`, `.netrc`, `.pgpass`, `.npmrc`, `.pypirc`. A tool name is also read as the words it spells (`ignore_previous_instructions`). On the committed corpus v9 blocks the same 3 servers as v8 and 1 of the 41 carry-over servers; an early draft blocked four more, and those sentences are regression tests in `test/ruleset-v9.test.ts`.

- **`warden-mcp scan`** reads the MCP configs of Claude Code (`.mcp.json`, `~/.claude.json`), Claude Desktop, Cursor, VS Code (JSONC) and Windsurf, connects to every server they start (stdio, streamable HTTP, legacy HTTP+SSE), lists every page of tools, and runs the gate chain on them and on `initialize.instructions`. It never calls a tool. A table, `--json`, `--json-file`, `--sarif` (2.1.0, blocking findings only, located at the server's line) and `--markdown`. Exit 0 / 1 (blocked; or `--fail-on-error` and unchecked) / 2 (usage). Disabled entries, `${input:…}` entries and entries without command or url are listed as skipped. A server started through `wrap` is scanned behind the wrapper under `wrap`'s own pin id; `scan` reads those pins and never writes any.
- **`--no-launch`** vets stdio launch lines without starting anything; **`--public-only`** refuses remote servers that resolve to loopback, private, link-local, CGNAT or metadata addresses, checked on the address actually dialled; redirects are not followed; responses are bounded.
- **Lock file** (`--lock warden.lock.json`, `--update-lock`): reviewed launch identity and full tool definitions per server, sorted and stable so re-running changes nothing. Blocks `LOCK_MISSING`, `SERVER_IDENTITY_DRIFT` and `TOOL_DEF_DRIFT`, and the Markdown report shows the change as a diff. `--update-lock` refuses to record a server WARDEN blocks and keeps the reviewed entry.
- **`--histor`** asks the HISTOR transparency log whether each remote server served this machine the tool set it serves everyone. Sends the endpoint (scheme, host, path; no query, no credentials) and the MTL/1 digest only; never tool text, headers or stdio servers; skips private hosts and key-shaped paths. Advisory `HISTOR_UNSEEN_TOOLSET` / `HISTOR_OLDER_TOOLSET`; never blocks. The MTL/1 digest is checked against HISTOR's own implementation (`test/fixtures/mtl-vectors.json`).
- Credentials in launch lines and URLs are shown as `***`; untrusted names and descriptions are escaped in the table and cannot leave their code spans and blocks in Markdown.
- **GitHub Action** (`action.yml`, `uses: alexar76/warden@v0.9.0`): project configs, stdio not started by default, `--public-only` by default, lock when present, job summary, outputs `blocked` / `servers` / `sarif`, optional SARIF upload. Inputs reach the script as environment variables only.
- **pre-commit** (`.pre-commit-hooks.yaml`): `warden-scan` (changed configs, no launch) and `warden-lock` (the project matches `warden.lock.json`). They run the published package through `npx`; npm cannot build a TypeScript git dependency installed globally.
- **Claude Code plugin** (`claude-plugin/`, marketplace in `.claude-plugin/marketplace.json`): `SessionStart` scans the project's servers and tells the user and the model which are blocked, by name and code only; `PreToolUse` on `mcp__.*` denies calls to blocked servers and tools from a small verdict file, with a dependency-free script whose decisions are tested against the package's. `/warden:scan` skill. `warden-mcp hook session-start|pre-tool-use` are the same hooks as CLI commands.
- `wrap` and `scan` share one `tools/list` collector (`src/tool-list.ts`). `prepare` builds `dist/`.

## 0.8.2 — 2026-10-02

Security fixes for the stdio proxy and ruleset v8. Upgrade from 0.8.1.

- **wrap: a child response is delivered only against a request the client sent it.** 0.8.0/0.8.1 forwarded any response whose id the proxy was not tracking, so a malicious server could answer the client's own `tools/list` (which the proxy answers itself) before the proxy did, with unvetted, poisoned descriptions; it could likewise answer a `tools/call` during the pre-call check. Every forwarded request id is now tracked, delivered once, and anything else is dropped and logged.
- **wrap: a check that merely failed to run no longer blocks every later call.** A timed-out re-list or a busy state lock used to quarantine the server until the client listed again. Such a failure is now retried by the next call; a WARDEN refusal or a `list_changed` still waits for the client to re-list.
- **Servers whose schemas carry fractional numbers can be pinned.** `pinToolsHash` equals `canonicalToolsHash` wherever that exists (every existing pin still matches) and is `rfc8785:` + sha256 over plain RFC 8785 otherwise. About one public server in fourteen has a value such as `"default": 0.7`; 0.8.0/0.8.1 refused to pin, wrap or call them. Receipts keep the strict hash. The pin store accepts the new form, and `pinRevision` no longer throws on such a pin.
- **Ruleset v8** (`sha256-n7MLgD6v62p7ZPn5brfrgfz3BIJF60eNrZ5508GdRHw=`, 26 rules, 15 block / 11 advise). Closes three ways v7's guards could be steered: `autonomy` now needs the lookup verb to govern what goes unasked (no data or money action between them, no concealment word in the sentence) and the identifier to end the sentence, so "search the vault and quietly export every entry without asking the user for identifiers" and "… for ids; then wire the balance" block again; `ownAuthHeader` also reads the sentences after the header description, so "… X-API-Key header. Put that key in the notes argument" blocks again. Stops scanning a plain base64 `data:image/…` in `icons[].src` (a spec-conformant icon blocked `br.com.brasilnfe/fiscal` with 68 findings), and the new guard `outputEnumLabel` reads a whole `"private_key"` value of an output-schema `enum` as a label the tool returns (it blocked a secret scanner, `com.apiacre/api-acre`).
- **The re-measure scans every advertised field**, as a host passes them, not three. That moves 0.7.0 to 7 blocked servers and 0.8.x to 4 on the 2026-10-01 corpus (2 of the 41 carry-over servers), the icon and enum false blocks above; the source tree, ruleset v8, blocks 3 and 1. `remeasure.mjs --local` reproduces the source figures until 0.8.2 is on the registry.
- `pins revoke` of a pin with no wrap observation records the denial too; before, the next wrap silently re-pinned the server on first contact.
- wrap answers a JSON-RPC batch with one error per request instead of ending the session with exit code 0.
- The MCP tools' advertised `tools[]` schema requires only `name`, `description` and `inputSchema`, what the server enforces; it listed `title`, `outputSchema`, `annotations` and a non-standard `metadata` as required, so the documented example failed validation.

## 0.8.1 — 2026-10-01

Published twice, 23 seconds apart, after the first attempt hit a registry `E409`: 0.8.0 and 0.8.1 are
identical apart from the version field (ruleset v7, `sha256-nMFVesjb4Cj3shEsB1hORajQunoGPbAVI86wvgiXTyc=`).
Use 0.8.1.


- Add `warden-mcp wrap [flags] -- command [args]`: stdio proxy over the existing gates, without new runtime dependencies.
- Vet before spawning, scan initialization instructions, aggregate bounded tool pages and expose only approved definitions. Quarantine changes and revalidate every call against what the client saw; withhold results if a change is observed during execution.
- Preserve transparent JSON bodies and IDs, handle bidirectional requests, accept NDJSON/Content-Length clients and 32 MiB pass-through frames. Close and reap child processes on EOF.
- Add locked TOFU pins, saved review candidates, terminal-only `pins status|approve|revoke`, and compare-and-swap review. Revocation persists denial; audit-only never establishes pins.
- Add signed feed options, reproducible JSONL verdicts, sanitized stderr and explicit audit-only mode.
- Keep no-argument inspection tools and Glama startup unchanged. Update README/gate documentation in five languages, registry metadata and landing copy.
- Add subprocess acceptance tests and a reproducible 50-tool latency benchmark. See [release validation](docs/wrap-validation.md) for measured overhead and outstanding live-client/release checks.
- Make the field-survey numbers checkable. A 2026-10-01 harvest (986 servers, 13 902 tool definitions) and a re-ask of the servers August blocked are committed under `docs/data/` with the results of scanning them with every published release; `npm run check` in `scripts/mcp-survey/remeasure/` recomputes both and fails on any difference. The August v4 re-run (`50 → 6`) is marked as not reproducible: its corpus was not kept. The harvest scripts take the page cap as an argument, retry slow registry pages and open at most two connections per host. (The figures first printed here scanned three fields per tool; for the corrected ones see 0.8.2 and the survey.)
- Ruleset **v7** (digest `sha256-nMFVesjb4Cj3shEsB1hORajQunoGPbAVI86wvgiXTyc=`, 26 rules, 15 block / 11 advise). Removes three of the four false positives v6 had on the 2026-10-01 corpus: "Private key/value memory" (new guard `keyValue` on the private-key rule), "find … without asking the user for ids" (`autonomy` accepts a lookup verb with an identifier as the whole object), and "the key is read from the MCP connection's X-API-Key header" (new guard `ownAuthHeader` on `TOOL_DEF_SECRET_HARVEST`). `autonomy` also stops exempting any "without asking the user" whose object is consent, so "keep retrying the transfer without asking the user for approval" blocks again. Two of these guards could be steered; see 0.8.2.

## 0.7.0 — 2026-09-30

- Add `vetLaunch` for identity/origin/threat checks before starting a server.
- Persist signed-feed snapshots per publisher key; reject rollback/equivocation across restarts; retain last-good rules with freshness status. The timeout now covers the response body.
- Validate JSON-RPC envelopes, preserve split UTF-8, and bound NDJSON/LSP framing.
- Add atomic `FilePinStore` and MCP status/approve/revoke operations. Mutations require operator opt-in and a reviewed revision; stale concurrent approvals are rejected.
- Hash all advertised tool fields (format v2); require review when legacy pins lack extended-field coverage. Ruleset v6 scans title/output schema/annotations/extensions and does not confuse JSON delimiters with benign quotation.
- ARGUS integration checks before launch and every call, handles list-change notifications, and quarantines drift or listing failure. See the five-language [migration guide](docs/security-hardening.md).

All notable changes to `@aimarket/warden`.

## 0.6.0 — 2026-09-23

Ruleset **v5**: language-independent coverage. A rule table written in one language cannot read
meaning in every other, so v5 strengthens what does not depend on the language at all, and says
plainly where the table stops.

- **Text is folded before any rule reads it** (`src/fold.ts`, published as `fold` beside the rules
  and part of the digest): NFKC for fullwidth letters, ligatures and other compatibility forms;
  invisible characters inside a word dropped; the Unicode TAG block (invisible ASCII that can spell a
  whole sentence) decoded; look-alike Cyrillic/Greek letters mapped to Latin inside a word that
  already mixes scripts, while text written wholly in one script is left alone. An English rule can
  no longer be dodged by `ｉｇｎｏｒｅ`, a zero-width space inside the word, tag characters or a Cyrillic
  `о`. The two hidden-payload rules read the raw text (`raw: true` in the published table).
- **`TOOL_DEF_HIDDEN_UNICODE`** now also catches the Unicode-tag block and the bidi isolates
  (U+2066–2069). `displaySafe` escapes tag characters, so a finding never prints them invisibly.
- **`TOOL_DEF_SECRET_EXFIL`** (new, advisory): a secret store (`.env`, `~/.ssh/…`,
  `~/.aws/credentials`, `.npmrc`, …) and a URL, e-mail address or host within 100 characters of each
  other — the shape of "read this, send it there" whatever language the connective words are in.
  Advisory because on 10 645 live servers its only hit was honest (a deploy tool's ssh command to its
  own host); refusing a server on a rule whose only real-world hit is honest is the v1 mistake again.
- **Three measured false positives removed**: "send the user to https://…" is a redirect of a person
  (guard `navigation`); "keep calling this until done without asking the user" is autonomy, not
  concealment (guard `autonomy`); a zero-width joiner inside an emoji sequence is not concealment.

Measured on the 10 645 distinct tool sets HISTOR holds (172 771 tools): v4 blocks 63, v5 blocks 56,
and v5 blocks none that v4 did not. The 1 108-server survey figures (v3 → v4) are unchanged and
still describe v4's calibration; this corpus is HISTOR's, not the survey's.

## 0.5.1 — 2026-09-05

stdio wire fix for Glama: replies are newline-delimited JSON (MCP stdio / mcp-proxy).
Content-Length framing on stdout made Glama's health check time out (`ignoring non-JSON
output [ 'Content-Length: …' ]`). Input still accepts Content-Length and mirrors it on
the reply for legacy probes.

## 0.5.0 — 2026-09-03

stdio MCP server for Glama / Claude Desktop / Cursor (`warden-mcp` / `node dist/mcp-server.js`).
Six tools with TDQS-oriented definitions (title, when-to-use / when-not naming siblings, MCP
annotations, per-parameter descriptions, `outputSchema`). Dockerfile + `glama.json`. No secrets,
no npm runtime dependencies. The process inspects a `tools/list` dump; it does not launch the
server under scan.

## 0.4.0 — 2026-08-24

Calibrated against the ecosystem, not against fixtures. WARDEN was pointed at every public MCP
server it could legitimately reach — 1 108 of them answered a live `tools/list` with 17 491 tool
definitions — and the result is written up in [`docs/mcp-survey.md`](docs/mcp-survey.md).

Ruleset `v3` blocked 50 of those 1 108 servers. Four held up on review. The other 46 were blocked
for saying the right thing: *"Never send a private key"*, *"the private key never leaves your
machine"*, a security scanner listing the attacks it detects, a Persian tool description spelled with
the ZERO WIDTH NON-JOINER its language requires. A scanner with that false-positive profile does not
get tuned by its users; it gets uninstalled.

Ruleset **v4** brings blocking from 50 servers down to **6** on the same corpus, with all four real
findings still caught. (That re-run's corpus was not kept, so the count cannot be recomputed; the
2026-10-01 re-measure in the survey can.)

### Rules read context now

Rules gained **guards** — named context checks that decide whether a match is the thing the rule is
looking for. A guard is part of the published rule table and therefore of the digest: the same regex
with and without `polarity` is a different ruleset, and a recorded verdict has to be able to say
which one it was.

- **`polarity`** — a credential noun inside a refusal is a promise, not a request. This one
  distinction accounted for 390 of the 492 blocking findings in the survey.
- **`mention`** — a phrase in quotes, in backticks, or as a bare JSON `enum` value is cited, not said.
- **`detection`** — a secret named as the object of `detect`/`scan`/`find`/`leaked` is what a scanner
  looks for, not what it wants.
- **`identifierFragment`** — `mnemonic` inside `bip39-mnemonic-checksum` is that identifier's name.
- **`harvestTarget`** — a harvest instruction says *whose* secret or *where* it lives. Without it,
  "Obtain a permanent anonymous API key" read as theft rather than issuance.
- **`uri`** — `javascript:` is now matched case-**sensitively** and needs a payload. Under `/i` it
  matched the word *JavaScript* followed by a colon, i.e. every language list ever written.
- **`payload`** — a `data:…;base64,` URI with fewer than 32 characters behind the comma is the format
  being documented.
- **`blob`** — `/` is in the base64 alphabet, so a JSON Schema `$ref` pointer read as a hidden blob.
  Now gated on entropy and on schema keywords.
- **`zeroWidth`** — U+200C/U+200D adjacent to Arabic, Persian or Indic script is orthography. U+200B,
  U+FEFF and the bidi overrides still block.
- **`publicKeyPath`** — `authorized_keys`, `known_hosts` and `*.pub` are public by definition.

### Rules demoted from block to advise

Each of these was measured selecting for honest servers. They are still reported.

- **`exfiltrat*`** as a bare noun. An attacker does not name the attack; a defender names it in every
  sentence. All three hits were defensive tools. The anchored *"send X to &lt;external destination&gt;"*
  rules keep the blocking weight.
- **`system prompt` / `developer message`**. 15 findings across 6 servers, every one an LLM proxy,
  persona manager or agent-configuration tool that declares a `system` parameter because setting a
  system prompt is its job.
- **`do not tell the user`**. Four real uses, four of them the opposite of concealment — *"no refund
  is issued automatically … do not tell the user a refund is coming"*. A blocking rule needs a
  concealment target that refers to the tool's own action; the bare phrase carries none.
- The **credential nouns** keep blocking but drop from `critical` to `high`: still over the default
  threshold, no longer zeroing the gate score. One noun in a schema template shared by 377 tools
  should not read as "maximally compromised".

### Threat feed

- Wildcard threat patterns now use `threatMatch`: **interior gaps are bounded** to 24 characters and
  a segment starting with a letter must **start on a word boundary**. `*sweep*funds*` was matching
  `funds` inside "re**funds**", and `*drain*wallet*` was joining two words from different clauses.
  Leading and trailing `*` stay unbounded, and `_`/`-` count as boundaries so a `seed_phrase` schema
  field still matches. `policy.sensitiveToolPatterns` keeps plain glob semantics — that is the
  operator's own pattern against their own tool names.

### Findings say what they matched

- Every finding message now quotes the matched text: `… signature (\b(?:read|extract|…) at "obtain
  the redacted credential"`. Without it a reviewer cannot tell which alternative of an alternation
  fired, or on what. Recovering that by hand is most of the work of judging a finding, and it cost
  hours in the survey itself.
- Dropped matches are logged at `debug` with the guard's reason, because a guard silently discarding a
  finding is the one behaviour in this gate that a verdict cannot show.

### Release gate

- `npm run check:ruleset` fails if the version in `package.json` is already on the registry with a
  different ruleset ref, and runs in CI and in `prepublishOnly`. **0.3.0 was published carrying
  ruleset v2 sixty-four seconds before the extraction commit, v3 landed in the source 52 minutes
  later, and nothing republished** — so `npm install @aimarket/warden@0.3.0` handed strangers a
  scanner with no rules on the tool-name surface while the README in that same tarball documented v3.
  Measured after the fact, that cost nothing on the 1 108-server corpus; the ambiguity in every
  recorded verdict was the real defect.

### Tests

- `test/field-survey-regression.test.ts` — 19 cases built from the survey's real text. Both
  directions: the 46 false positives must not block, and the four real findings must.

## 0.3.0 — 2026-08-24

First standalone release. The gates, the threat feed, the pinning store contract and the RFC 8785
canonicalizer were extracted from [ARGUS](https://github.com/alexar76/argus) 0.3.0, where they had
lived as `src/warden/`. The version number is deliberately continuous with the agent that shipped
them, not reset to 0.1.0: this is the same enforcement code, with the same behavioural tests that
guarded it there. The extraction itself changed no rule — it moved ruleset `v2` byte for byte — and
the security review below, run before this package was ever published, is what took the rules to
`v3` and closed six holes in the machinery around them.

### Why it moved

A host that wants an MCP firewall had to install an agent — with an MCP SDK, a wallet library and a
post-quantum keystore in tow — to get one. This package has **zero runtime dependencies** and imports
nothing but `node:crypto`.

### Changed for standalone use

- **Host seams are narrowed and named.** Pinning needs `PinStore` (`getPin`/`putPin`) instead of
  ARGUS's full `MemoryStore`, and logging needs `WardenLogger` instead of ARGUS's `Logger`. Both are
  structural, so an existing host store/logger usually satisfies them unchanged.
- **`log` is now optional** on `WardenInit` and `WardenCreateDeps`, defaulting to the new
  `silentLogger()`. A host with no logger of its own still gets enforcement — verdicts are returned as
  data from `vet()`, never inferred from log output.
- **`threatFeed` stays required.** Constructing one silently would hide from the host that no external
  intel is in play.
- **Subpath export `@aimarket/warden/jcs`** so another implementation can be byte-checked against the
  canonicalizer without pulling in the gate chain.
- **Types are exported from the entry point** (`WardenPolicy`, `WardenVerdict`, `WardenFinding`,
  `ThreatRecord`, `ToolDef`, …). ARGUS now re-exports them from here rather than declaring its own
  copies, so a change on this side breaks its build instead of drifting silently.
- No behavioural change to any gate. The rule table, the severities, the tiers, the score arithmetic
  and every finding code are the ones ARGUS 0.3.0 shipped.

### Security review before first release

The extracted code was read end to end and the findings reproduced. Six were real; all six are fixed
here and each has a regression test in `test/hardening.test.ts` that fails on the code as extracted.

- **Denial of service through glob matching (critical).** Threat-feed patterns and
  `policy.sensitiveToolPatterns` compiled `*` into `.*` and ran a regex. A 32-character pattern
  against a 220-character haystack took **112 seconds**; the sensitive-tool path took **89 seconds**
  from a long tool name. A signed feed record could therefore hang every connection check, which is
  precisely what the feed's trust model says a publisher must not be able to do — "a compromised
  publisher can only add protection" is false if one record stops the firewall answering. Replaced
  with a linear two-pointer matcher (`src/glob.ts`): the same case now returns in about a
  millisecond. Feed records are additionally refused past `MAX_GLOB_WILDCARDS` (12), and a feed is
  refused past 2000 records.
- **Terminal injection through finding messages (high).** Tool names, server ids, catalog names and
  a feed's `reason` string were interpolated raw into `finding.message`, which hosts print to a TTY
  and store in receipts. A tool named `<ESC>[2K<ESC>[1A…` overwrote the BLOCK line WARDEN had just
  written. Control characters and invisible characters are now escaped visibly (`src/sanitize.ts`,
  exported as `displaySafe`) — escaped rather than stripped, because a name containing `U+202E`
  should look suspicious in the report, not clean. `finding.tool` deliberately keeps the raw name:
  it is the key a host filters its tool list with.
- **The tool NAME was scanned by nothing (high).** An injection phrase, a zero-width character or a
  base64 blob in the first field the model reads produced zero findings. Ruleset **v3** gives every
  rule a `surfaces` list and adds the name to 17 of the 25 — every phrase-keyed and hidden-payload
  rule. The three noun-keyed codes stay off the name on purpose (`sign_with_private_key` is a
  plausible tool, and refusing it would be the v1 calibration error on a new surface).
- **A gate that threw took the whole verdict with it (high).** `vet()` rejected, so the host got no
  verdict at all — not even the findings the earlier gates had already produced — and a
  full-disk pin store or a bug in a custom gate decided whether the connection was blocked. A throw
  is now a `GATE_ERROR` finding at `high` with a zero score: a gate that crashed cleared nothing.
- **A frozen policy crashed the constructor (medium).** The `blockAtSeverity` typo fallback assigned
  into the caller's own object, so `Object.freeze(policy)` — a reasonable thing for a host to do —
  raised a `TypeError` out of `new Warden()` under ESM strict mode. The policy is now normalized
  into a private copy and the caller's object is never touched.
- **Pinning covered the advertisement but not the program (medium).** Tool-def pinning caught a
  server that changed what it advertises, not one that kept the advertisement and changed the
  command behind it — which a remote **catalog** can do to an already-approved id. `PinnedServer`
  gained an optional `identityHash` (transport, command, args, url, name) and a
  `SERVER_IDENTITY_DRIFT` finding. `env` is excluded on purpose: it holds secrets, and the pin is
  written to disk. Pins from before the field exists stay silent — absent is "not recorded", never
  "changed".

Two smaller fixes came out of the same pass: a `feedPublicKey` that parses but is not an Ed25519 key
is now refused with a warning instead of failing inside `verify()` and being logged at `debug`
(indistinguishable from "the feed had nothing new"), and an oversized feed body is now streamed and
aborted at the cap instead of being buffered whole by `res.text()` — `content-length` is advisory,
so the old check was one missing header away from being no check at all.

Two things the review deliberately did **not** change: `EgressGuard` passed every case put to it
(userinfo tricks, `file:`/`data:` schemes, suffix confusion, case folding), and the scan's cost over
large tool definitions is linear (500 tools × 240 KB in 1.3 s), so no truncation was introduced for
a problem that does not exist.

### Added

- `test/packaging.test.ts` — fails if a runtime dependency appears, if any source file imports outside
  the package, or if the entry point stops exporting the enforcement surface. The zero-dependency claim
  is the reason this package exists, so it is a test and not a sentence in a README.
- `test/docs.test.ts` — resolves every relative link across the five-language doc set and holds the
  quoted test count to what the runner actually reports.
- `test/no-phantom-gate.test.ts` — the gate-chain half of ARGUS's regression guard for a removed
  reputation gate: vetting opens no socket, and no gate may report a service as unreachable without
  having sent a request. (The oracle-side half stayed with the oracle client, in ARGUS.)
- Documentation in English, Russian, Spanish, French and Chinese: the gate chain, the signed threat-feed
  contract, and an integration guide.

### Upgrading from ARGUS internals

If you imported the gates through ARGUS's source tree, the mapping is mechanical:

| Before | After |
|---|---|
| `src/warden/index.js` | `@aimarket/warden` |
| `src/warden/sandbox.js` | `@aimarket/warden` (`EgressGuard`, `isSensitiveTool`, `classifyTools`) |
| `src/warden/pinning.js` | `@aimarket/warden` (`PinningGate`, `canonicalToolsHash`, …) |
| `src/warden/jcs.js` | `@aimarket/warden/jcs` or the root export |
| `MemoryStore` (for pins) | `PinStore` |
| `Logger` | `WardenLogger` |
