# WARDEN MCP security benchmark — 2026-11-07

**Status: five-product comparison complete on both hosts.** Each product attempted all 18,110 rows. Complete-result coverage, errors and case-level agreement are reported separately; mixed-cohort totals are not accuracy figures. The later `.2` runtime-only candidate has its own validation status below.

[English](security-benchmark-2026-11-07.md) · [Русский](security-benchmark-2026-11-07.ru.md) · [Español](security-benchmark-2026-11-07.es.md) · [Français](security-benchmark-2026-11-07.fr.md) · [中文](security-benchmark-2026-11-07.zh.md)

This benchmark is authored by the maintainer of both WARDEN and HISTOR, with AI assistance. It is a maintainer-run comparison, not an independent certification. The comparative measurements reported here are remote gVisor measurements. An earlier local pilot is excluded, and its generated `dist`/Vitest/Vite artifacts were removed. This report does not claim that no local pilot ever existed.

## What is being compared

The common comparison is **high/critical definition signals and any relevant definition signal**. Only products with an enforcement decision are described as blocking. Definition scanning is distinct from executing tools, observing a model follow an injection, or measuring an attack's success against a model.

| Implementation | Package / entry point | Fresh version identity |
|---|---|---|
| WARDEN, primary published product | `@aimarket/warden` | npm `0.23.0`, ruleset `17`, 40 rules; digest `sha256-UOfK25xo6D8vrKEVfNFBTBVn5OspyaZut9vC9Z9Q5JE=` |
| mcp-audit | PyPI `mcp-audit-scanner[mcp]` | `0.28.0` |
| mcp-shield | npm `mcp-shield` | `1.0.4` |
| truecopy | npm `@askalf/truecopy` | `0.10.5` |
| mcpsentry | npm `@roshan6335/mcpsentry` | `0.1.5` |

The primary WARDEN artifact is the verified published npm tarball, SHA-256 `833841f2aab89df4c51b5f84385ad69c8ffd7dcf5a7725ec0eb4ebabe594b7ee`. The earlier frozen “v17” build has six changed distribution files for wrapper/result screening and is **not byte-identical to npm 0.23.0**. Its candidate-history results do not replace the published-product column. The unpublished post-hoc candidate is `0.23.1-dev.20261107.1`, ruleset `19`, 43 rules including 32 blocking, digest `sha256-XfRh1+VZoAM6PGtbmqprnSX/eF16qNYOk0o+ilRFxXw=`. Initial v18 is retained separately with digest `sha256-aXkZQj8F1fKgcTpyrfNdgQSQMuzdc1yabcKiGPVKjMo=`. No npm publication occurred.

Published packages and upstream public corpora are obtainable. Exact replay of the maintainer fixtures and adapters requires their source release. Bundle metadata supports inspection of row identities, thresholds, coverage and output hashes; it does not itself enable full independent replay. Candidate19 source also remains unpublished: its hashes and receipts are auditable evidence, not an externally reproducible build. Public artifacts contain reports, metadata and figures, without product or private harness source.

Prior results remain in [the historical comparison](scanner-comparison.md). Its mcp-audit `0.18.2` and truecopy `0.10.4` pins must not be substituted for this run's versions; unchanged version numbers for other packages are also freshly verified identities.

## Inventory: real implementations and replayed definitions

The large comparison uses the actual implementations' native classifier/full-analysis APIs on frozen advertised definitions, with fresh state. It does **not** claim that each of the 18,110 targets traversed stdio MCP separately for every product. Native CLI/MCP parity and live interoperability are separate checks.

| Category | Explicit targets | What is exercised | Fresh status |
|---|---|---|---|
| Installed stdio implementations, candidate19 | `@modelcontextprotocol/server-filesystem@2.2.0` (16 tools), `@modelcontextprotocol/server-memory@2.1.0` (9), `@modelcontextprotocol/server-sequential-thinking@2.1.1` (1), WARDEN (9) | Official Node MCP SDK `1.32.1`; each package directly and wrapped; discovery, one safe synthetic call, unknown-tool refusal and subsequent ping | Both hosts: 8/8 sessions, 4/4 direct/wrapped tool-list digest pairs equal |
| Public HTTP implementations, candidate19 | DeepWiki (3 tools), Microsoft Learn (3), Cloudflare Docs (2) | `initialize` and `tools/list` only; no advertised tool invoked | Both hosts: 3/3 completed without error, all three allowed |
| Frozen-definition analysis | 3,177 fixed views plus 14,933 HISTOR package rows | Actual native full-analysis/classification implementations, not execution of upstream tool code | Complete on both hosts |
| Representative CLI/MCP parity | Node competitors: 10/10 per product; Python mcp-audit: 13 native/API agreements through the default six-analyzer pipeline, including one partial result; published WARDEN: 20/20 including a 1.17 MB list and attack/clean/repeat cases | Native entry points compared with bulk adapters | Agreement on a partial result is not a complete verdict |

See [live evidence](../../artifacts/warden-security-2026-11-07/live/README.md). Final candidate19 SDK receipts use the remote `sdk19-final` run; the local `sdk19` copies retain the initial run. These observed package versions are not a claim to latest upstream releases. Synthetic calls use isolated test data, not user files or production credentials. HTTP discovery used `https://mcp.deepwiki.com/mcp`, `https://learn.microsoft.com/api/mcp` and `https://docs.mcp.cloudflare.com/mcp`.

## Exact fixture inventory

**Maintainer-written attacks: 23 cases.** IDs refer to the definitions in [`build_sets.py`](../scripts/scanner-comparison/build_sets.py):

`A01-important-tag`, `A02-ssh-into-param`, `A03-shadowing-bcc`, `A04-zero-width-hidden`, `A05-unicode-tags`, `A06-base64-payload`, `A07-russian`, `A08-chinese`, `A09-paraphrase`, `A10-schema-hidden`, `A11-annotation-injection`, `A12-exfil-url`, `A13-name-injection`, `A14-private-key-param`, `A15-seed-phrase`, `A16-javascript-url`, `A17-ignore-previous`, `A18-system-tag`, `A19-call-first-history`, `A20-env-dump`, `A21-destructive`, `A22-concealment`, `A23-spanish`.

**Maintainer-written benign controls: 12 cases.**

`B01-never-send-key`, `B02-injection-scanner`, `B03-api-key-param`, `B04-javascript-word`, `B05-persian-zwnj`, `B06-refunds`, `B07-send-email`, `B08-secret-scanner`, `B09-password-vault`, `B10-upload-drive`, `B11-ssh-howto`, `B12-translate`.

**Third-party fixtures: 10 attacks, one benign and one ambiguous case.**

| Source | Cases and label |
|---|---|
| mcp-audit, commit `fdc8762eb2d5abb708bdaf767ec5a8140b2ab9a2` | Attacks: `behavioral_override_stealth`, `cloud_credential_exfiltration`, `crowdstrike_add_numbers`, `fake_postmark_exfiltration`, `invariant_labs_ssh_exfiltration`, `xml_injection_override` |
| mcp-shield, commit `379140c3555bf35c6f8f451ee320da24302e792e` | Attacks: `calculateSum`, `sendEmail`, `readFile`, `getFactOfTheDay`; benign: `whatsapp`; ambiguous: `fetchWeather` |

The ambiguous fixture is excluded from attack-recall and benign-error denominators. Its verdict is still reported. Third-party authorship does not make a known fixture a new holdout: these inputs have been available during WARDEN development.

## MCPTox: extraction, counts and all 45 server names

The archived extraction contains **485 distinct poisoned tool definitions**: 267 on the 22 development servers and 218 on the 23 test servers. The separate decorated set has 225 definitions whose prompt representation differs from the served definition. The clean-control set contains 45 server tool lists. These units must not be combined into a single “server count”.

The paper's **1,348 scenarios** are a different, overlapping view from 485 distinct definitions. The remote audit of official commit `f85189f9ad12504c197c7f920ab818a40657b1fa` retained all 1,348 rows: 1,338 unique server/frame values plus 10 retained duplicate instances, with zero discarded. Of these, 702 used literal line feeds and 646 required escaped-line-feed normalization. The two raw JSON hashes match the archived values below. The source repository specifies no license, so public downloads contain factual metadata, not raw MCPTox definitions, schemas, payloads or Python source. Full prompt-surface and served-definition measurements remain separate. See [the extraction code](../scripts/scanner-comparison/build_mcptox.py) and [the archived split](../scripts/scanner-comparison/results/2026-10-09-mcptox.json).

The full-frame scenario projection retains argument text verbatim but represents extracted parameter properties as strings. It does not reconstruct the original native argument types; full-frame findings therefore apply to that declared projection, not an exact execution of the original server schemas.

**Development servers — 22:** AWSKnowledgeBase; AdFin; AlphaVantage; BaiduMap; ClickHouse; Codacy; Commander; DoDo Payments; Email; EverArt; Everything; Fetch; Flomo; Google Maps; Memory; Prisma; SQLite; Sentry; Slack; Tavily; gNucleus Text to CAD; mcp-simple-arxiv.

**Test servers — 23:** 12306-mcp; AgentQL; AmapMap; Apify; BraveSearch; Claude Post; DumplingAI; E2B; FileSystem; Financial Dataset; Git; Github; Gitlab; GoogleDrive; Gyazo; HyperBrowser; KeywordsPeopleUse; OP.GG; Puppeteer; QuickChart; Redis; Sequential Thinking; wechat.

These are dataset names, not claims of present connectivity or affiliation. The split was fixed by ascending `sha256("mcptox split 2026-10-09|" + server_name)`, first 22 development, remaining 23 test. The lists above use the ordering preserved in the results file.

Archived source-byte SHA-256 values:

| Input | SHA-256 |
|---|---|
| `pure_tool.json` | `54b1eb0e9d7b2f18465266aa9d9dfda828cd558b1269b74731ec2c5d8579e617` |
| `response_all.json` | `79a90049be931c59e71446d6180b1d7f0d196d123d08a59bc155d142b5041c03` |

The parser reads upstream definitions as data and does not execute their Python code. “Served” uses the extracted server definition; “decorated” separately measures prefixes such as `<IMPORTANT>` or “Ignore the previous instructions”. The 45 normalized clean lists contain 362 tools; this differs from the paper's stated 353, and deduplication by name+description or full definition does not remove the discrepancy. Neither count is silently substituted for the other.

## Archived public servers and package observations

The main archived field cohort is **986 public server tool lists** from [the 2026-10-01 corpus](data/mcp-corpus-2026-10-01.jsonl.gz). The separate [August carryover archive](data/mcp-corpus-2026-10-01-august-carryover.jsonl.gz) contains **41** observations, including **28 exact name+definition overlaps**, leaving **999 unique name+definition snapshots**. They remain separate cohorts; adding 986 and 41 does not establish 1,027 independent servers.

The [full metadata inventory](../../artifacts/warden-security-2026-11-07/inventory/README.md) explicitly lists **all 18,110 target rows**, including names, recorded package versions, labels, tool counts, digests and provenance. Downloads: [CSV.gz](../../artifacts/warden-security-2026-11-07/inventory/public-inventory.csv.gz), [JSON.gz](../../artifacts/warden-security-2026-11-07/inventory/public-inventory.json.gz), [file hashes and set counts](../../artifacts/warden-security-2026-11-07/inventory/public-inventory-manifest.json). These metadata-only downloads do not redistribute unlicensed attack content.

The frozen **14,933 HISTOR package-version rows** are available: **12,023 npm and 2,910 PyPI**, referencing **14,449 distinct toolsets and 272,657 tool records**, with no discarded rows or count mismatches. Exact MTL digest rederivation and case-file hashes passed on both hosts. The 2026-10-20 [archive](https://histor.modelmarket.dev/datasets/2026-10-20/toolsets.jsonl.gz) and [signed manifest](https://histor.modelmarket.dev/datasets/2026-10-20/manifest.json) recovered 14,930 rows; three missing digests were recovered from immutable public API URLs. The archive is CC-BY-4.0, attributed to Aleksandr Artamokhov / HISTOR, *HISTOR: MCP tool definitions and how they change*, snapshot 2026-10-20. The three API responses state no separate license and remain metadata-only in public downloads. Signatures were checked against HISTOR's pinned `did:key`.

Historical inputs use the exact archived MTL base fields; no current title, annotations or extension fields were merged into them. Package observations are not fresh installs or live executions. An unlabelled package/public corpus measures block frequency; false-positive conclusions require labels or relevant-text adjudication. Historical sample judgments do not establish fresh whole-cohort precision.

| Frozen input / proof | SHA-256 |
|---|---|
| 3,177-view catalog | `e29baa05fbdbf46e34631ff2c75f0b4f535f0188054dd4499699bd189a3dc757` |
| 14,933-package catalog | `78d4dab7125318b80cc35302e7cf1cfc1a49fa6f310957ed7b8fddfb538375b6` |
| HISTOR recovery proof | `8cdb0faf62c72f947baf30f74d6523fc6fd5b68720b44f4b765a0f804489cf7e` |
| Final grouped results | `44732cdfa369f0f912491212d1910883a6071c4ce4727cfc30911adb828d7a3b` |
| Final case-level host proof | `a0773f6622290268129cc48323dab0b1b84dc5652d1b2b1ba20e679c63a01205` |
| Final SHA-256 manifest | `17d6e7ebd85dede970d77f319bf3734478a037bf9fd971a53f5bbd07b4fce3f8` |

The catalogs use `warden.shared-lazy-inputs/v1`. `toolsFileSha256` hashes exact UTF-8 bytes; `toolsSha256` hashes Python 3.13 sorted-key compact JSON with Unicode preserved and non-finite values refused, **not a claimed JCS serialization**. Array order is retained. Portable verification can use the exact file bytes. Wire ids are `c` plus the first 32 hex characters of SHA-256 over `warden shared inputs 2026-11-07|` followed by the case key, identical across products, versions and hosts.

## Recorded remote protocol

1. Freeze source identity, ruleset digest, scanner package versions, registry resolution time, published integrity hashes, installed dependency inventory and container image digest before interpreting results. Keep the scanner's original output and command.
2. Freeze a manifest of SHA-256 hashes for every input byte stream: raw archive/download, extracted definition, generated replay JSON, labels, split, config and harness. Use stable case ids. Record transformation versions and provenance; a dataset name alone is not an input identity.
3. Bulk scans used `runsc`, network none, UID/GID 501:501, read-only root/source/runtime/data, dropped capabilities, no-new-privileges, isolated tmpfs and dedicated writable results. Image `sha256:db7085498187e8477fa462d5f1652d62bdf4b8af29ea3666bd1748a8315631a5` contains Node 24.22.2/Python 3.13.18. Node comparators used 1 CPU/768 MiB; a retained Node receipt has pids 128. Audit base used 1 CPU/768 MiB; HISTOR used attested 1 CPU/768 MiB/one worker and PingBlip 2 CPU/1,536 MiB/two workers, pids 256. Linux `cpu.max`/`memory.max` were checked; timings are not a controlled speed comparison. Audit HISTOR UTC windows: attested 20:33:21–21:13:27, PingBlip 20:33:15–21:34:48 on 2026-11-07. Live stdio used separate UID1000, 0.5 CPU/512 MiB restrictions; HTTP used bridge/256 MiB and public-address restriction. Do not conflate phase settings.
4. Pass each frozen target to the actual native full-analysis/classification API with fresh state. mcp-audit runs its default six analyzers, not just a poisoning regex subset. Validate adapters with the scoped native CLI/MCP checks above. WARDEN uses recorded `allowUnknownServers: true` and `sensitiveToolPatterns: []`. truecopy cold-lock/unpinned refusals are separate from content classification. Keep live discovery separate and hash captured responses.
5. Preserve first attempts, errors and retries separately. Predeclare timeout and retry policy. An error, skipped target or protocol rejection is not an allow verdict. Never substitute an earlier release's verdict for a missing fresh result.
6. Retain raw outputs, normalized verdicts, errors and output-hash manifests before cleanup. Final cross-host proof compares each key, opaque wire id, exact input-file SHA-256, package/source/image identity, status, HC/any/advisory booleans and canonical full native-result SHA. Only mcp-audit's own temporary config `finding_path` and fresh `RUGPULL-000` state-file evidence are normalized; finding text, codes and severities remain represented.

[Download the report and data ZIP](https://modelmarket.dev/blog/media/warden-security-comparison-2026-11-07/reports-and-data.zip) for offline EN/RU/ES/FR/ZH reports, `grouped-results-v2.json`, `figure-cross-host.json`, methods and metadata-only per-case outcomes. Public outcomes contain statuses, flags and hashes; retained full native findings and unlicensed payloads are not promised as public downloads.

mcp-audit bulk invokes native `run_scan_async(extra_paths=[fresh_config], connect=True, guardrail_drift=True)`. Only `mcp_client.connect_and_enumerate` is substituted with captured objects validated as the installed SDK's `ListToolsResult` and converted through native `_tool_info`; default analyzers, toxic-flow, delegation, annotation checks and scoring remain enabled. Each case has fresh HOME/cwd/config/rug-pull state. Optional online/API/LLM analysis is off; a 30 s timeout retires the worker and records an incomplete outcome. WARDEN's native policy is `blockAtSeverity=high`, `allowUnknownServers=true`, `sensitiveToolPatterns=[]`, `pinToolDefs=true`.

## Verdicts and denominators

| Scanner | Definition-related content threshold; original output remains authoritative |
|---|---|
| WARDEN | Native `allow: false`, including static-scan and threat-feed definition gates, under the recorded policy |
| mcp-audit | Definition-related `HIGH` or `CRITICAL` findings from the full default analysis pipeline |
| mcp-shield | Tool reported as `HIGH Risk` |
| truecopy | Native HIGH/CRITICAL content findings; any content finding, including advisory, can be classified poisoned/withheld by the proxy; cold-lock/unpinned refusal is separate |
| mcpsentry | Tool-definition finding at `HIGH` or `CRITICAL` |

The common threshold column means a **high/critical signal**, not identical enforcement. WARDEN has a native allow/block decision and truecopy content classification relates to proxy withholding; their enforcement outcomes remain recorded separately. mcp-shield's CLI can exit 0 with findings. mcpsentry exits 1 for critical findings, while a high-only result can exit 0. Therefore these report-only tools' high/critical signals must not be called enforced blocks.

Report **threshold-positive**, **below-threshold/advisory-only**, **no relevant finding**, **error/partial**, **skipped**, and **not run** separately. “Any finding” includes threshold positives. A scanner warning caused solely by the harness path, config hygiene or first-scan baseline is preserved and excluded by the same stated rule for every scanner.

The audit retained normalization-v1 diagnostics: it incorrectly excluded three legitimate WARDEN threat-feed SSH critical detections by selecting static-scan alone. Normalization-v2 includes all relevant definition gates; raw engine outputs were unchanged. Only first-scan `TOOL_DEF_UNPINNED` info was excluded on observed WARDEN data. Consistent harness/launch/baseline exclusions prevent a meaningless 100% any-signal rate from pinning noise. Final tables show high/critical signals and any relevant definition signal; below-threshold/advisory-only is any minus threshold-positive among complete results.

For each scanner/cohort show scheduled `N`, complete results `C`, threshold-positive `B` (the retained JSON field), below-threshold/advisory-only `A`, errors/partial `E`, skips `S` and unrun `U`: `N = C + E + S + U`, `C = B + A + no-finding`. Threshold-signal rate is `B/C`; it is recall only within attack-labelled cohorts. Coverage is `C/N`, always with raw counts. With errors, also show `B/N`, without treating errors as true negatives. Benign threshold-positive frequency uses complete benign cases; enforced-block frequency is a separate product-specific measure. False-positive claims require labels or adjudication. Ambiguous cases stay separate.

MCPTox attacks are counted per definition; clean MCPTox, public and carryover results per server snapshot; HISTOR per package target. A threshold-positive target has at least one relevant tool finding at the selected threshold; tool-level finding counts are additional diagnostics.

### Partial scans, protocol compatibility and deadlines

Two HISTOR mcp-audit records hit native analysis budgets: 5,000 schema nodes / depth 64 and 65,536 characters of per-tool text. They belong in `E` as **partial**, excluded from complete-result coverage and primary `B/A` totals, even when their partial outputs contain findings. Partial signals remain separately inspectable; a native/API agreement on a partial result does not turn it into a complete scan.

mcp-shield uses strict MCP SDK schema validation: 31 historical package lists are rejected before analysis. mcpsentry and truecopy use native raw JSON-RPC without that validator. mcpsentry's CLI and API both accepted a 42-tool case rejected by mcp-shield, with zero findings. This is a real protocol-compatibility difference, not an adapter silently dropping cases. For mcp-shield's HISTOR phase, attested completed 14,902/14,933 (31 schema errors); PingBlip completed 14,901/14,933 (31 schema errors and one timeout). Both reported 5,354 HC / 6,767 any signals among complete cases. These are unlabelled positive frequencies, not false-positive rates.

A separate 3 MB mcp-shield native/API parity case passed in 52.18 s after its combined harness deadline was raised from 30 to 90 s; each engine call took roughly 28 s. The first combined timeout is retained. The actual per-case API budget remained 30 s. That combined-deadline retry is not a detector failure or a hidden change to the bulk timeout policy.

## Fresh results

### First measured WARDEN candidate: a regression, retained

The initial ruleset-v18 candidate lost three served-definition detections relative to v17. `FileSystem_20`, `FileSystem_22` and `FileSystem_23` are newly missed. These measured failures are retained; a later repair is a separate, post-hoc candidate and cannot be reported as an unseen-holdout result.

| Surface / unit | Earlier frozen v17 build blocked | Initial v18 blocked |
|---|---|---|
| 485 native served definitions | 460/485 | 457/485 |
| Known historical test split, 218 definitions | 210/218 | 207/218 |
| 225 decorated definitions | 225/225 | 225/225 |
| 1,348 full prompt-surface scenarios, including duplicate rows | 1,331/1,348 | 1,331/1,348 |
| 45 clean servers, 362 tools | 0/45 | 0/45 |

Both hosts matched. Actual-MCP versus library-path parity was 2,103/2,103 cases per version per host, 8,412 comparisons in total. This is path/host parity, not model attack-success evidence. The remote final-report receipt is `/opt/warden-tests/20261107-mcptox-v18/results/final-report/REPORT.md`; the later paired report below provides expanded verified coverage. No npm release is implied.

The verified post-hoc ruleset-v19 candidate is narrower than blocking public-key references: it addresses forced overwriting of SSH public-key files as security-configuration tampering and reads of `/etc/shadow` as secret-store access. It recovers `FileSystem_20` and `FileSystem_23`; `FileSystem_22`, the public-key-read prerequisite, remains a nonblocking tool-hijack limitation. That attack is neither relabelled benign nor removed from its denominator. A public-key read alone remains non-secret. All three initial v18 misses stay in the record.

| Candidate19 view | Native WARDEN blocks / completed | Errors |
|---|---|---|
| Own attacks / benign controls, separately | 23/23; 0/12 | 0 |
| Third-party attacks / benign / ambiguous, separately | 10/10; 0/1; 0/1 | 0 |
| Served native definitions | 459/485 | 0 |
| Known historical test split | 209/218 | 0 |
| Full prompt-surface scenarios | 1,331/1,348 | 0 |
| Decorated definitions | 225/225 | 0 |
| Clean server lists | 0/45 | 0 |
| Public-main / carryover, separately | 3/986; 1/41 | 0 |

Both versions (v18/v19), both hosts, each actual-MCP/library path comparison: **3,177/3,177**. Full cross-host compared rows: **12,708/12,708**, with all seven input/source/harness/replay identity checks true. This is verified operational/path parity, not complete attack detection. See [candidate19 report](../../artifacts/warden-security-2026-11-07/candidate19/REPORT.md). Report SHA-256: `e699ba593242406b31f366b34d3e104dcf567094fd97421a62fbba8ded958989`; paired JSON SHA-256: `30996c170fd4284991ac4624ee88cda765ae26cb2393a8bbdeefa23913847a4e`.

### Final five-published-product results

Cells are **HC / any / advisory-only counts**; advisory-only = any − HC. All base rows have `C=N`, `E=S=U=0`. The HISTOR coverage exceptions are in the following table. HC/any counts match across hosts, including the extra complete negative Shield case on attested. WARDEN means **published npm 0.23.0 / rules17**. Overlapping views are never summed into “all attacks” accuracy.

| Cohort and scheduled unit | WARDEN npm 0.23.0 | mcp-audit 0.28.0 | mcp-shield 1.0.4 | truecopy 0.10.5 | mcpsentry 0.1.5 |
|---|---|---|---|---|---|
| 23 own attacks | 20 / 23 / 3 | 11 / 13 / 2 | 6 / 10 / 4 | 3 / 8 / 5 | 4 / 4 / 0 |
| 12 own benign controls | 0 / 3 / 3 | 1 / 2 / 1 | 1 / 2 / 1 | 1 / 1 / 0 | 2 / 2 / 0 |
| 10 third-party attacks | 10 / 10 / 0 | 10 / 10 / 0 | 8 / 9 / 1 | 1 / 7 / 6 | 5 / 5 / 0 |
| 1 third-party benign | 0 / 0 / 0 | 0 / 0 / 0 | 0 / 0 / 0 | 0 / 0 / 0 | 0 / 0 / 0 |
| 1 third-party ambiguous | 0 / 0 / 0 | 0 / 0 / 0 | 0 / 1 / 1 | 0 / 0 / 0 | 0 / 0 / 0 |
| 485 served MCPTox definitions, all | 460 / 474 / 14 | 56 / 392 / 336 | 56 / 71 / 15 | 1 / 31 / 30 | 19 / 19 / 0 |
| …267 dev definitions | 250 / 257 / 7 | 17 / 214 / 197 | 15 / 25 / 10 | 1 / 4 / 3 | 11 / 11 / 0 |
| …218 known historical-test definitions | 210 / 217 / 7 | 39 / 178 / 139 | 41 / 46 / 5 | 0 / 27 / 27 | 8 / 8 / 0 |
| 225 decorated MCPTox definitions | 225 / 225 / 0 | 222 / 225 / 3 | 41 / 95 / 54 | 135 / 141 / 6 | 136 / 136 / 0 |
| 1,348 full prompt-surface scenarios | 1331 / 1338 / 7 | 951 / 1264 / 313 | 158 / 570 / 412 | 432 / 491 / 59 | 460 / 460 / 0 |
| 45 clean MCPTox servers | 0 / 7 / 7 | 0 / 3 / 3 | 3 / 6 / 3 | 0 / 0 / 0 | 1 / 7 / 6 |
| 986 archived public servers | 4 / 388 / 384 | 43 / 159 / 116 | 343 / 451 / 108 | 2 / 39 / 37 | 86 / 450 / 364 |
| 41 carryover observations | 2 / 37 / 35 | 12 / 24 / 12 | 33 / 35 / 2 | 1 / 3 / 2 | 21 / 38 / 17 |
| 14,933 historical package rows | 409 / 6327 / 5918 | 481 / 2089 / 1608 | 5354 / 6767 / 1413 | 15 / 252 / 237 | 1449 / 6362 / 4913 |

### Complete-result coverage and exact host agreement

Each primary product has `N=18,110` per host, `S=U=0`, and 18,110 paired input identities. There are zero missing, input-identity mismatches, engine-identity mismatches or differing complete results. The denominator for agreement excludes incomplete outcomes.

| Product | C attested / PingBlip | E attested / PingBlip | Identical / comparable complete pairs | Error pairs |
|---|---|---|---|---|
| WARDEN npm | 18110 / 18110 | 0 / 0 | 18110 / 18110 | 0 |
| mcp-audit | 18108 / 18108 | 2 / 2 | 18108 / 18108 | 2 partial on both |
| mcp-shield | 18079 / 18078 | 31 / 32 | 18078 / 18078 | 31 schema on both; 1 timeout only PingBlip |
| truecopy | 18110 / 18110 | 0 / 0 | 18110 / 18110 | 0 |
| mcpsentry | 18110 / 18110 | 0 / 0 | 18110 / 18110 | 0 |

Supplemental candidate19 `.1` matches on all 18,110 complete paired rows; supplemental v18 HISTOR matches on 14,933/14,933. Candidate19 HISTOR is 407 HC / 6327 any / 5920 advisory-only, versus published WARDEN 409 / 6327 / 5918. No v18→v19 HISTOR verdict changed. Narrow review of the two published17→v18 allowed passages found legitimate public-key provisioning in `@krovacloud/mcp@0.3.16` (`create_cube`, `sshPublicKey`) and `@runpod/mcp-server@4.4.0` (`update-ssh-keys`, `keys`). That judges those passages, not whole-package safety; raw text is not redistributed.

Author-labelled 35 and independent 12 are mixed cohorts; their unsplit totals are block frequency, not attack recall. The final label-specific rows above use 23/12 and 10/1/1 respectively. Live interoperability belongs to candidate19 evidence above and is not a cell in the five-product classification table.

## Candidate validation and provenance

Earlier v18 regression validation passed 1,517/1,517 tests in 62 files on both hosts, plus typecheck/build; its separate red-team gate reported 0/28 delivered. This is not the five-product model attack-success rate. The broad whole-directory witness was incomplete because a sibling corpus-reporting script changed; the executed product and 1,090 captured source/test/script files were stable.

Candidate19 passed **1,536/1,536 tests in 63 files on both hosts**, with typecheck/build/red-team exit codes 0 and no OOM: attested 288.085 s, PingBlip 558.354 s. Initially, 1,534 detector tests passed while stale README/landing rule-count metadata caused retries. The validation copy changes only count metadata in five README files, with no detector changes; 521 runtime/source/test files are byte-identical, digest `f4732e8beb77342ae250ac11126859ef59cf5e9bf3d74e8e46221b8d856d3231`. This validates the frozen benchmark candidate, not every pre-existing change in the current workspace. Initial diagnostics and the interrupted obsolete PingBlip attempt remain retained separately; no pristine-whole-workspace claim is made.

## Later runtime-compatibility build .2

`0.23.1-dev.20261107.2` is separate from frozen `.1`: it accepts valid MCP blob-resource contents without optional `mimeType`, while continuing to screen metadata/structured lookalikes. Both hosts passed **1,536/1,536 tests in 63 files**, typecheck/build/red-team exit 0; full-suite times were attested 293.705 s and PingBlip 554.284 s. Both passed 304 focused tests at normal 1 CPU with unchanged deadlines, and SDK 8/8 sessions with 4/4 direct/wrapped list pairs. The earlier 0.25-CPU setup timeout is retained; it did not recur at normal capacity.

Independent binary/SDK checks preserved a valid 400k blob both with and without MIME metadata. Invalid plaintext/object-blob/poisoned-metadata results were withheld after one execution while the session stayed alive; this is result-screening compatibility, not a claim that tool side effects were prevented. The representative 23 CLI/library checks match `.1`/`.2` findings and scores. The 320 source/distribution files outside the changed result-screen module are byte-identical to `.1`, SHA-256 `5ff407cf78742ae18fd593065e9c9bd552bba45f3fab91f27fae9f45adb13238`, and the rules19 digest is unchanged. The `.1` 18,110-row classification remains the measured row; it is not relabelled as a `.2` run. Both sources remain unpublished.

The current working snapshot `0.23.1-dev.20261108` adds Codex/OpenCode hooks absent from frozen `.1` and `.2`. Its acceptance validation is separate. None of the 18,110-row measurements or frozen-build quality receipts is presented as a measurement of those November 8 additions.

## Limits on the final interpretation

Own fixtures were written by WARDEN's authors, and third-party fixtures have been read during development. The MCPTox test split is a **known historical holdout**, not a newly unseen test set: results have been published repeatedly, and the templates are shared with development cases. Fresh reuse does not restore blindness. Any claim that later rules did not use test inputs needs a retained provenance audit; phrase-overlap checks alone cannot prove independence.

Archived public and package definitions do not establish present server behavior. Discovery does not test tool execution or dependency safety. Static blocks do not measure model attack-success rate, end-to-end protection, secret exfiltration prevention, or resistance to every attack family. Optional classifier or model experiments, if performed, require their own model/version, prompts, budget, request evidence and denominator; none are implied by this report's static tables.
