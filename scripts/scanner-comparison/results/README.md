# Scanner comparison results

Two runs are kept here. The write-up is [`docs/scanner-comparison.md`](../../../docs/scanner-comparison.md).

| Run | Files |
|---|---|
| 2026-10-09: WARDEN 0.8.2 / 0.9.0, mcp-audit 0.18.2, mcp-shield 1.0.4, on a workstation | `2026-10-09.json`, `2026-10-09-mcptox.json`, `judgments-2026-10-09.json` |
| 2026-10-16/17: WARDEN 0.16.0 (ruleset v12), mcp-audit 0.18.2, mcp-shield 1.0.4, truecopy 0.10.4, mcpsentry 0.1.5, in gVisor on two servers | everything below |

## The 2026-10-16 run

### Files

| File | What |
|---|---|
| `manifest-2026-10-16.json` | written before the runs: SHA-256 tree hash of every input set, the harness files, the WARDEN tarball, both image IDs and their base, each scanner's version, registry integrity and whether its installed files match the published package, the competitor image's full `pip freeze`, the hosts, the container flags, the HISTOR snapshot and the package split |
| `manifest-files-2026-10-16.txt.gz` | SHA-256 of each of the 16,830 input files |
| `packages-index-2026-10-16.json.gz` | the 14,933 HISTOR package targets: id, name, endpoint, version, `toolSetDigest`, and which host ran it |
| `packages-judged-subset-2026-10-16.json` | the 996 packages in which every block was judged |
| `2026-10-16.json` | summary and per-server blocks for our sets, their fixtures, the corpus and the packages, plus `run`: where each set ran, every retry, what is still an error, the cross-host check, the held-out check, the classifier and its cost |
| `2026-10-16-mcptox.json` | MCPTox verdicts by case id, the split and the classifier summary; the dataset itself is not copied here |
| `judgments-2026-10-16.json` | every judgment, 2026-10-09's included. A judgment with `scanners` was made by reading what those scanners matched, and counts only for them |
| `classifier-judgments-2026-10-16.json` | the classifier's `high` findings on the 200-server corpus sample and the package sample, read and judged |
| `raw-2026-10-16.tgz` (not in git) | every raw scanner output and WARDEN report as copied back from both hosts, except the MCPTox sets (their outputs quote the dataset): first passes, retries, the aborted attempt and the smoke run kept apart. 70,209 files, 25,549,682 bytes, sha256 `6a8b2c9025763922be627870581012c2a6843fa7163191cc7092b4ed53b7396b`. It is kept outside the repository so every clone does not carry 25 MB of raw output; every number here comes from the files above. Ask for it in an issue |
| `logs-2026-10-16/` | the hosts' queue logs (start, end, exit, CPU and worker settings of every container), the parallelism probe and the hub watchdog log |

### Where it ran

- **Containers.** Built once on PingBlip from [`Dockerfile.competitors`](../Dockerfile.competitors) and
  [`Dockerfile.warden`](../Dockerfile.warden), copied to attested with `docker save | docker load`, so both hosts
  ran the same image IDs. Flags: `--runtime=runsc --network none --memory 2g --memory-swap 2g --pids-limit 512
  --read-only --tmpfs /tmp:size=512m`, user `node`, one bind mount `/opt/warden-cmp/20261016:/work` (inputs read-only
  to the container user, raw outputs written there). One scanner container at a time per host.
- **attested** (6 cores, shared with the attestedmemory hub and other services, runsc release-20261005.0):
  labelled, independent, corpus, the three MCPTox sets, `packages-b` (10,056 packages), the 100-package cross-host
  set and all retries. `--cpus 4` until about 16:15Z on 2026-10-16 (the running MCPTox-decorated container was then lowered to 2 with
  `docker update`), and `--cpus 2 --cpu-shares 256` for every container from 17:17Z on.
- **PingBlip** (6 cores, shared with the PingBlip game and HISTOR's package sandbox, runsc release-20261005.0):
  `packages-a` (4,877 packages), the cross-host set, and a corpus run started before the manifest that is kept only as
  a cross-check. `--cpus 3`.
- **Split.** A package goes to PingBlip when `int(sha256(target id), 16) % 3 == 0`, otherwise to attested; the
  cross-host set is the 100 targets with the smallest `sha256("warden cross-host 2026-10-16|" + id)`.
- **Workstation.** The set builders, the HISTOR read (public API only, nothing queued on its sandboxes), the
  classifier runs (the containers have no network) and the summaries. WARDEN also ran there as a pilot; its verdicts
  equal the container's on every fixed set and are not published.

### Timings (UTC)

| Host | Set | Container time |
|---|---|---|
| attested | labelled, independent (four scanners) | 13:28–13:33, 2026-10-16 |
| attested | WARDEN on all six fixed sets | 13:32–13:36 |
| attested | corpus (four scanners) | 13:36–15:24 |
| attested | MCPTox served / decorated / clean | 15:25–16:02 / 16:02–17:17 / 17:17–17:22 |
| attested | packages-b | 17:23–04:44 (paused 19:26–04:45 by the hub watchdog), resumed 04:45–15:18, 2026-10-17; WARDEN 15:18–15:44 |
| attested | cross-host set; retries | 15:44–15:53; 15:53–16:40 |
| PingBlip | packages-a | 18:58, 2026-10-16 – 14:44, 2026-10-17; WARDEN 14:44–15:23 |
| PingBlip | cross-host set | 15:23–15:51 |

### What was retried, and what is still missing

A run that ended in a timeout, not a verdict, was run once more in a fresh container from the same image, and the
retry's verdict is the one counted. Nothing else was rerun or merged.

| First pass | Timeouts | Retried on |
|---|---|---|
| attested, corpus | mcpsentry 327, mcp-shield 24 (2026-10-16 14:04–14:37, while the host was overloaded) | attested |
| attested, MCPTox decorated | mcp-shield 28 (the minutes around a pause) | attested |
| attested, packages-b | mcp-audit 3, mcp-shield 1 | attested |
| PingBlip, packages-a | mcp-audit 800, mcp-shield 10 | attested |

mcp-audit 0.18.2 gives each server a fixed 10 seconds to connect (`connect_and_enumerate(timeout=10.0)`, no option).
On PingBlip, next to HISTOR's sandbox, 6 parallel runs missed it on every server and 2 parallel runs on 800 of 4,877,
so those were retried on attested, where 6 parallel runs had no timeouts. A first PingBlip attempt with 6 workers
(18:36–18:57) was stopped and its raws kept apart in the tarball, never merged.

**Still without a verdict:** 26 packages (8 in `packages-a`, 18 in `packages-b`) for mcp-shield only. Its MCP client
rejects their tool lists (`inputSchema.type` is not `"object"`), so it checks nothing; this is the scanner's behaviour,
not a timeout, and was not retried. **Nothing was cut:** every set ran with all five scanners.

### Checks

- **Cross-host:** on the 100-package set both hosts gave identical verdicts and finding codes for all five scanners,
  100 of 100. On the corpus, where both hosts produced a verdict: mcp-shield 962/962, truecopy 986/986, mcpsentry
  475/475 identical.
- **Against 2026-10-09:** mcp-audit and mcp-shield give the same verdicts on labelled, independent, the corpus and
  MCPTox served and clean, although mcp-audit's dependencies now resolve to the MCP Python SDK 2.x. WARDEN v12 gives
  v10's verdicts server for server.
- **Held-out:** no rule written since v10 saw MCPTox's test half (method in `2026-10-16.json` → `run.held_out_check`).
- **WARDEN tarball:** byte-identical to `@aimarket/warden@0.16.0` as published on npm.

### Incidents and limits

- The attestedmemory hub hung on 2026-10-16 from 14:05 to 14:42 and again around 16:12, while our attested container
  was in its heaviest phases at `--cpus 4`. After that the run was capped at `--cpus 2 --cpu-shares 256`, the hub got
  CPU priority, and a watchdog on the host paused our containers whenever the hub's median latency stayed above 2 s.
- The watchdog paused `packages-b` at 19:26; the driver that should have resumed it ran on a workstation and died, so it
  stayed paused until 04:45. It resumed in a fresh container that ran only servers without a raw file.
- The classifier ran once per set: $1.71 in all, read from the provider's balance (one aborted attempt on the
  package sample, $0.05, produced nothing).
- The judged package sample is the morning draw of 1,000, kept where the afternoon fetch served the same
  `toolSetDigest` (996). For mcp-shield's 339 blocks there we read the evidence each block reports, together with the
  classifier's reading of the whole definition; every other block was read at the text the scanner matched, in its
  tool's description or schema.
