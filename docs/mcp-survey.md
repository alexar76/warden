# What WARDEN found in 1 108 public MCP servers — and what it got wrong

> 🌐 **English** · [Русский](mcp-survey.ru.md) · [Español](mcp-survey.es.md) · [Français](mcp-survey.fr.md) · [中文](mcp-survey.zh.md)

On 2026-08-24, hours after publishing `@aimarket/warden` 0.3.0, we pointed it at every public MCP
server we could legitimately reach: 2 787 servers listed in the official registry with a network
endpoint, of which 1 108 answered a real `tools/list` and handed us 17 491 tool definitions.

The headline is not about the ecosystem. It is about us. WARDEN blocked 50 of those 1 108 servers,
and in **4** of the 50 could we substantiate a genuine concern. The other 46 are our scanner being
wrong, in six ways we can name, reproduce and fix.

We are publishing the failures with the evidence because a scanner's false-positive profile is the
only number that decides whether anyone can switch it on. A tool-poisoning scanner that refuses
honest servers is not a cautious scanner; it is a scanner that gets uninstalled, and ruleset v1
already taught us that once.

## What was measured

| | |
|---|---|
| Package under test | `@aimarket/warden@0.3.0`, installed from the npm registry into an empty project — not the working tree |
| Ruleset in force | v2, `sha256-gWC14PR4kUylkJaAGMnIYYX6tPhZTJ60cSB61UZxuWc=` (see [the release defect](#the-release-defect) below) |
| Corpus | `registry.modelcontextprotocol.io`, 8 000 rows → 3 121 unique servers → 2 787 with a remote endpoint |
| Acquisition | MCP `initialize` + `tools/list` over streamable-http, one attempt per server, 20 s timeout |
| Gates run | `static-scan` and `threat-feed` (built-in deny-list, no remote feed) |
| Gates not run | `origin` and `pinning` — both decide on *host state* (did the operator declare this server, did its defs drift since approval), neither is a property of the server, and in a survey both would return the same answer for all 1 108 |
| Policy | `blockAtSeverity: "high"`, `allowUnknownServers: true`, `pinToolDefs: false` |

**No third-party code was executed.** Every tool definition came from the server's own answer over
the network. This is why the corpus is remote servers and not the stdio servers in the various
awesome-lists: reaching those means downloading and running a stranger's code, which is not
something a security survey gets to do casually.

### Reachability — a finding in its own right

Only 41% of the registry's advertised remote endpoints completed a handshake:

| Outcome | Servers |
|---|---|
| answered `tools/list` | 1 149 (41.2%) |
| refused with 4xx (auth required, or gone) | 1 215 |
| connect / TLS failure | 298 |
| `sse` transport, not attempted | 37 |
| 5xx | 34 |
| protocol mismatch (no usable `initialize` result) | 21 |
| redirect / 410 / 429 | 32 |

Of the 1 149 that answered, 1 108 advertised at least one tool. Anyone building a client against
the registry should size their retry and auth handling for a **59% first-contact failure rate**.

## Results

| | Servers | Findings |
|---|---|---|
| scanned | 1 108 | 3 964 |
| clean | 664 | — |
| findings but allowed | 394 | 3 472 advisory |
| **blocked** | **50** | **492 blocking** |

Blocking findings by rule. A server can trip several rules, so the server column does not sum to 50:

| Code | Findings | Servers | After review |
|---|---|---|---|
| `TOOL_DEF_SECRET_REQUEST` | 401 | 13 | 4 substantiated, 9 polarity-blind |
| `TOOL_DEF_DATA_URL` | 31 | 11 | all false — `JavaScript:` and image-API examples |
| `TOOL_DEF_INJECTION` | 21 | 13 | all false — `system prompt` as domain vocabulary, honesty instructions |
| `TOOL_DEF_SECRET_HARVEST` | 14 | 10 | all false — verb+noun collocation, 30-char window |
| `THREAT_CRYPTO_DRAINER` | 9 | 4 | all false — substring wildcards |
| `TOOL_DEF_HIDDEN_UNICODE` | 5 | 1 | all false — Persian ZWNJ |
| `TOOL_DEF_BASE64_BLOB` | 3 | 2 | all false — JSON Schema `$ref` pointers |
| `THREAT_SEED_PHRASE` | 3 | 2 | all false — substring wildcards |
| `TOOL_DEF_EXFIL` | 3 | 3 | all false — security tools naming the attack |
| `THREAT_SSH_KEY_READ` | 2 | 1 | all false — documented `ssh -i` invocation |

Counted by server rather than by finding, because one boilerplate line repeated across 377 tools is
one defect, not 377. The four substantiated cases all sit under the two credential rules.

## What held up

Four servers advertise tools that really do move secret material through the model's context. We
describe them without naming them: they are not misbehaving, they are doing a legitimate job in a
way an agent host should genuinely gate, and a survey is not a disclosure venue.

- A prediction-market treasury server whose tool takes `signer_private_key`, described as
  *"signer EOA private key, 0x…"*. A wallet signing key, requested as an API parameter. This is
  precisely the case WARDEN exists for.
- An agent-to-agent payments server that provisions a sandbox wallet and *"return[s] its private
  key exactly once"* through the tool channel.
- An agent-identity server whose tool prose instructs the model to read a local
  `credentials.json` and to write `private_key` JWKs to disk with `chmod 0600`.
- A managed-database server with a `pvkPassword` parameter — *"Password that encrypts the private
  key"*. A documented parameter of a major cloud API, and still a credential in a tool schema.

That is 4 of 50 blocked, or 4 of 1 108 scanned. Everything below is the other 46.

## What did not hold up

### 1. Polarity blindness — the biggest single defect

`TOOL_DEF_SECRET_REQUEST` matches the noun phrase `private key`. It does not read the sentence
around it. So these were all blocked at `critical`. At the default threshold both `high` and `critical` refuse
the connection — the whole server, every tool — and `critical` additionally takes the gate score to
zero:

> Never send a private key: none is needed and the request is refused if one is present.
> — a DANE/TLSA record generator

> Use this to import your own public key so you can SSH into instances. **The private key never
> leaves your machine.**
> — a cloud instance manager

> YOU sign and broadcast the returned transaction yourself, with your own wallet's private key, on
> your own infrastructure — **Otto never sees or holds your key**.
> — a swap-quote server

> …does NOT confirm the certificate matches any private key.
> — a certificate inspector

> Use exact field names from this schema; **do not guess aliases or include private key material.**
> — a SAP protocol server, in the schema boilerplate of **all 377 of its tools**

That last one is the whole shape of the problem in one line: a server that tells the model *not* to
send private keys is scored identically to one that asks for them, and because the rule is
`critical`, a single noun match in shared boilerplate refused the server and took it to score 0.00. 390 of our 492 blocking findings are this one noun.

`TOOL_DEF_SECRET_HARVEST` — a verb from `read|extract|retrieve|fetch|obtain|dump|reveal|collect|…`
within 30 characters of a credential noun — fails the same way:

> Anyone holding the URL can read it, so **never store secrets**, credentials or personal data
> — a temporary-storage server

> Public read-only: **never collect card data, secrets or email**
> — a booking-advisory server

> it does **not** reveal or mint a standalone agent credential
> — an agent-registration server

Three servers were blocked for promising, in writing, not to do the thing the rule is looking for.

### 2. Role blindness — the scanners get blocked

A tool definition that *describes* an attack is scored as though it *performs* one. Five servers,
all of them defensive tooling:

> …for prompt-injection and social-engineering (`'ignore previous instructions'`, `'send funds to'`,
> `'approve this'`, `'admin override'`, `'claim your airdrop'`…)
> — an instruction checker, blocked on `ignore previous`

> hidden directives that hijack agents — instruction overrides, `'don't tell the user'`, data
> exfiltration, secret harvesting, tool-shadowing, and invisible-unicode / homoglyph steganography
> — an MCP endpoint scanner, blocked on `exfiltration`

> `"enum": ["exfiltration", "recon_then_destroy", "injection_then_action"]`
> — a policy builder, blocked on its own enum values

> Detect likely leaked API keys, tokens, private-key headers, JWTs…
> — a secret scanner, blocked on `private-key`

An attacker writes a poisoned tool without naming the attack. A defender names it in every
sentence. Our rules select for the defender.

### 3. "do not tell the user" is an honesty instruction

The `TOOL_DEF_INJECTION` rule treats `do not tell the user` as concealment. In every real instance
we found — four servers, four for four — it is the opposite: the server is stopping the model from
telling the user something *false*.

> some convert in real time during the session, others batch once or twice daily, so **do NOT tell
> the user** a payment is "held until the next session"

> AFTER payment succeeds, no refund is issued automatically — the result says so explicitly; **do
> not tell the user** a refund is coming

> a `facturx-en16931` result is the payload and not a Factur-X document — **do not tell the user
> otherwise**

> **Do not tell the user** to drag assets into chat

The premise of the rule is inverted on real data. Conscientious server authors use the phrase to
suppress hallucinated reassurance, which is exactly the behaviour an agent host wants.

### 4. Vocabulary collisions

- **`system prompt`** → `TOOL_DEF_INJECTION`, 15 findings across 6 servers. Every one is an LLM
  proxy, persona manager or agent-configuration tool whose entire purpose is to set a system
  prompt, and which declares a `system` parameter in its schema. The word is the domain, not the
  attack.
- **`\bjavascript:`** with the `i` flag → `TOOL_DEF_DATA_URL`, high. It matches the word
  *JavaScript* followed by a colon, which is how every language list on earth is written:
  *"TypeScript/JavaScript: `*.spec/test.{ts,js}`"*, *"plain async JavaScript: …"*,
  *"javascript: Enable JavaScript execution"*. It also fires on servers that advertise stripping
  the scheme: *"the sanitizer strips … `javascript:` and `data:text/html` URIs"*.
- **`data:…;base64,`** → the same rule, on image APIs whose schema example is literally
  `"<url> OR data:image/png;base64,..."`, and on a scraper that says it *filters out* `data:`
  schemes.
- **the 30-character window** in `SECRET_HARVEST` jumps sentence and JSON boundaries:
  `read an open or sealed run (pass api_key` is a match spanning a prose sentence into a
  parameter name.

### 5. Encoding blindness — WARDEN flags a writing system

`TOOL_DEF_HIDDEN_UNICODE` reports "zero-width or bidi control characters hiding text from review".
One server tripped it five times. It is an Iranian legal-calculation server, and the character is
**U+200C ZERO WIDTH NON-JOINER** — a *required* orthographic character in Persian:

- `بخشنامه‌ها` (circulars)
- `سهم‌الارث` (inheritance share)
- `حق‌الثبت` (registration duty)
- `حق‌التحریر` (notary fee)

Nothing is hidden. That is how the language is spelled. As written, the rule penalises Persian,
Arabic and Indic-script servers for their orthography — a security control that reads as a language
policy, which is worse than a false positive.

`TOOL_DEF_BASE64_BLOB` has the mirror-image bug: `/` is in the base64 alphabet, so a deeply nested
JSON Schema pointer — `#/properties/flow/items/anyOf/2/properties/outcomes/items` — is reported as
"a long base64-encoded blob — possible hidden payload".

### 6. Threat-feed wildcards match substrings

The built-in deny-list uses `*a*b*` wildcards against the concatenated tool definition, with no
word boundaries and no proximity:

- `*sweep*funds*` matched an ENS floor-sweeping tool: *"Floor-sweep: buy the CHEAPEST N listed ENS
  names"* … *"and **refunds** the excess"*. The pattern found `funds` inside **refunds**.
- `*drain*wallet*` matched an anti-drainer scanner: *"Find risky allowances that could **drain**
  your tokens"* … *"a **wallet** granted"*. The tool exists to stop drainers.
- `*seed*phrase*` matched a YouTube keyword tool: *"For a **seed** topic, returns suggested search
  **phrases**"*.

All three are reported as `critical` with the message *"Crypto-drainer keyword in server identity"*
— which is also wrong about *where* it matched: these hit the tool definition, not the server
identity.

## What worked exactly as designed

The one part of the ruleset that survives contact intact is the **tiering**. `advisory` findings
fired 3 472 times — `TOOL_DEF_CREDENTIAL_PARAM` 2 016, `TOOL_DEF_IMPERATIVE` 1 437,
`TOOL_DEF_ENV_REFERENCE` 19 — and blocked nothing, cost no score, and quarantined no tool. Under
ruleset v1, where `api_key` in a schema was blocking, those 2 016 hits would have refused a large
share of the honest ecosystem. The v1→v2 lesson holds up on real data; the block-tier rules are
where the work remains.

## The release defect

The package we scanned with reports ruleset **v2**, digest `sha256-gWC14PR4…`. The README **inside
that same tarball** documents ruleset **v3** and prints the digest `sha256-pah/sT4I…`. Both are
true statements about different code:

| | |
|---|---|
| `0.3.0` published to npm | 2026-08-24 08:34:08 UTC |
| commit that extracted the package | 2026-08-24 08:35:12 UTC — 64 seconds later |
| commit that introduced ruleset v3 | 2026-08-24 09:26:50 UTC — 52 minutes after publish |

So the artifact strangers install has no rules at all on the `name` surface, where v3 carries 17 of its 24 rules; a zero-width character or a base64 blob in a tool *name* is invisible to it.

Then we measured what that costs. We re-ran the identical corpus against a v3 build and compared
per-server, per-tool, per-code:

**Zero difference.** 444 servers with findings, 50 blocked, 3 964 findings — identical under both
rulesets. Not one of the 1 108 real servers puts anything in a tool name that v3 catches and v2
misses. The stale publish is a real process defect — the CI guard for it is item 9 below — and on this
corpus its behavioural impact is nil, and we would rather say so than imply a severity we did not measure.

## What changed because of this

All of it shipped as ruleset **v4** in `@aimarket/warden` 0.4.0, digest
`sha256-klRyTiD3njdBs7sOjcDCfmAHaKsfQi75/wlQjjWWkXI=`. Rules now carry named **guards** — context
checks that decide whether a match is the thing the rule is looking for. A guard is part of the
published rule table and therefore of the digest, because the same regex with and without `polarity`
is a different scanner and a recorded verdict has to be able to say which one it was.

| Guard | Decides |
|---|---|
| `polarity` | A credential noun inside a refusal is a promise, not a request — the clause around it, and the match itself, are checked for a refusal cue |
| `mention` | A phrase in quotes, in backticks, or as a bare JSON `enum` value is cited, not said |
| `detection` | A secret named as the object of `detect` / `scan` / `find` / `leaked` is what a scanner looks for |
| `identifierFragment` | `mnemonic` inside `bip39-mnemonic-checksum` is that identifier's name |
| `harvestTarget` | A harvest instruction says *whose* secret, or *where* it lives |
| `uri` | `javascript:` is matched case-**sensitively** and must be followed by a payload |
| `payload` | A `data:…;base64,` URI with fewer than 32 characters behind the comma documents the format |
| `blob` | Entropy floor and schema keywords, so a `$ref` pointer is not a hidden payload |
| `zeroWidth` | U+200C/U+200D adjacent to Arabic, Persian or Indic script is orthography |
| `publicKeyPath` | `authorized_keys`, `known_hosts` and `*.pub` are public by definition |

Four blocking rules were demoted to advisory, because each was measured selecting for honest servers:
the bare `exfiltrat*` noun, `system prompt` / `developer message`, `do not tell the user`, and — in
severity only, from `critical` to `high` — the credential nouns, so one noun in a shared schema
template no longer reads as "maximally compromised".

The threat feed got its own matcher: interior wildcard gaps are bounded to 24 characters and a
segment starting with a letter must begin on a word boundary. `_` and `-` count as boundaries, so a
`seed_phrase` schema field still matches while `funds` inside "refunds" does not.
`policy.sensitiveToolPatterns` keeps plain glob semantics — that is the operator's own pattern
against their own tool names.

Finding messages now quote the matched text. Ours used to truncate the pattern to
`signature (\b(?:read|extract|…)`, so a reviewer could not tell which alternative fired or on what.
Recovering that by hand was most of the work of this survey.

### Re-measured on the same 1 108 servers

| | ruleset v3 (as surveyed) | ruleset v4 (re-run, not published) |
|---|---|---|
| servers blocked | 50 | **6** |
| of those, substantiated | 4 | **4** |
| blocking findings | 492 | 12 |
| advisory findings | 3 472 | 3 494 |
| servers with any finding | 444 | 439 |

**Which half of that table you can check.** The v3 column is derivable from the dataset in this
repo. [`data/mcp-survey-2026-08-24.json`](data/mcp-survey-2026-08-24.json) records the run as
executed — `@aimarket/warden@0.3.0` from the registry, `ruleset.version: "2"`, 50 blocked, 444 with
findings, 3 964 findings — plus a `ruleset_v2_vs_v3` block establishing that v3 changed nothing on
this corpus: `servers_with_new_findings: 0`, `newly_blocked: []`, *"same 444 servers with findings,
same 50 blocked, same 3 964 findings"*. That is why the column is labelled v3 while the file says v2.

The v4 column is **not** in this repo, and no committed file records it. It was measured here against
the same collected tool definitions, but that collection is not committed — `scripts/mcp-survey/`
ships the harness, not its output, so the only v4 artefact is this table. Treat those five numbers as
our measurement reported in good faith, not as something you can recompute from this tree. The
`50 → 6` figure quoted on the landing page and in the READMEs inherits exactly that status.

What *is* reproducible, and what the claim actually rests on, is the **direction**.
[`test/field-survey-regression.test.ts`](../test/field-survey-regression.test.ts) holds the verbatim
descriptions of the servers behind the 46 false positives and behind the 4 substantiated findings,
and asserts both ways: under v4 the false positives no longer block, and every one of the four real
findings still does. It runs under `npm test` with no network and no corpus. It is built from this
corpus's actual text rather than from fixtures, because nobody sitting down to invent test data would
write "the private key never leaves your machine" or spell a description with a Persian ZERO WIDTH
NON-JOINER.

A corpus-wide v4 count would need a fresh harvest, and it would not land on 6 even if the ruleset
were perfect: 1 215 of the 3 121 registry servers answered `4xx` on the day, and which ones do that
is a property of the day rather than of the rules.

### What still fires, and why we left it

Two of the six remaining blocks are still ours:

- A blockchain-forensics tool named `wallet_funds`, on the built-in `*drain*wallet*` pattern. Its
  description asks *"did they drain the project wallet"* — the two words genuinely are adjacent, so a
  proximity bound cannot help. This is role blindness at the threat-feed layer, and the feed has no
  notion of a defender. Giving signed threat records a guard mechanism is a larger change to the
  feed's trust model than this pass should make.
- A cloud host's `get_ssh_command`, on `~/.ssh` inside a documented `ssh -i ~/.ssh/<keypair_name>`
  invocation. A tool definition pointing the model at the user's SSH key directory is arguably worth
  a flag; blocking on it is arguably not. Left as-is rather than tuned by one example.

### The release gate

`npm run check:ruleset` fails if the version in `package.json` is already on the registry carrying a
different ruleset ref. It runs in CI and in `prepublishOnly`, and the first time it ran it caught the
live defect described above: 0.3.0 published as v2, source at v4. Changing the rules now requires
changing the version.

## Limitations

- **One transport.** streamable-http only; 37 `sse` servers were skipped, and every stdio server in
  the ecosystem is out of scope by the no-execution rule. stdio servers are the majority of what
  people actually run locally.
- **One point in time.** A single `tools/list` per server on 2026-08-24. Tool definitions change,
  and a server that is honest at fetch time can rotate a description later — which is what the
  `pinning` gate is for, and pinning is exactly what this survey could not exercise.
- **"False positive" is our judgement.** We read the tool definition and decided the flag was
  wrong. We did not audit the servers, and a false positive on the *definition* does not certify
  the *implementation*: a tool whose prose is impeccable can still exfiltrate on invocation.
  Static scanning of tool defs cannot see that, by construction.
- **No ground truth.** Nothing in this corpus is labelled. We can report that 46 of 50 blocks were
  wrong; we cannot report how many poisoned servers we walked straight past. False negatives are
  invisible to this method, and a 4/50 precision figure says nothing about recall.
- **Auth-gated servers are absent.** 1 215 servers refused without credentials. Those are
  disproportionately the commercial ones, so the corpus skews toward open and hobby servers.
- **The v4 re-measure is not reproducible from this repo.** Only the v2/v3 run is committed as data.
  The v4 column, and the `50 → 6` headline everywhere it appears, rest on a local re-run whose raw
  output is not published; the regression suite reproduces the direction, not the counts. See
  [Which half of that table you can check](#re-measured-on-the-same-1-108-servers).

## Reproduce it

Nothing here needs our infrastructure or a key. The scripts are in
[`scripts/mcp-survey/`](../scripts/mcp-survey/) and the aggregate is in
[`data/mcp-survey-2026-08-24.json`](data/mcp-survey-2026-08-24.json).

```bash
cd scripts/mcp-survey
python3 harvest_registry.py          # registry -> registry_remotes.json
python3 harvest_tools.py             # live tools/list -> tools_raw.jsonl
npm install @aimarket/warden@0.3.0
node scan.mjs tools_raw.jsonl scan.json
python3 classify.py                  # exact matched span per blocking finding
```

`harvest_tools.py` makes two or three requests per server and executes nothing. If you re-run it,
your reachability numbers will differ from ours — endpoints come and go by the hour.

The pin above is `0.3.0` deliberately: it reproduces the survey as published, ruleset v2. Swap it for
`@aimarket/warden@0.4.0` and you get ruleset v4 — but on **your** corpus, harvested on **your** day,
so the result is your own measurement rather than a check of ours. That is the honest state of the v4
column: we cannot hand you the corpus it was computed on.

## Baseline

For the record, so the next reading of these numbers means something. On 2026-08-24, the day of this
survey and the day 0.3.0 was published:

| | |
|---|---|
| npm version | 0.3.0, published 08:34 UTC |
| npm downloads of 0.3.0 | none recorded — the registry's counters run through 2026-08-23, so no data for it exists yet |
| npm downloads, prior week | 1, of the `0.0.1` name placeholder |
| GitHub stars | 0 |

Whatever these numbers are the next time this page is updated, that is where they started.
