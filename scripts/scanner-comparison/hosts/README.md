# Host scripts of the 2026-10-16 run

What ran on the two servers, as it ran. Paths are the run's work directory, `/opt/warden-cmp/20261016`.

| Script | Role |
|---|---|
| `prep_work.py` | copies replay sets and the harness into a work directory and rewrites every config to `node /work/harness/replay.mjs /work/sets/<set>/<key>.json` |
| `prep_packages.py` | splits the HISTOR package set into `packages-a` / `packages-b` and picks the 100-package cross-host set |
| `write_manifest.py` | writes `results/manifest-2026-10-16.json` from the hashed inputs and the recorded tool facts |
| `run_set.sh` | one set in one fresh container: `competitors` (the four scanners in turn), `warden`, or `resume` (continue after a pause; only servers without a raw file run). Reads `cpus.cap`, `cpu.shares` and `workers.conf` at each start |
| `chain.sh` | runs `SET:MODE:CPUS` steps one at a time, never while another `warden-cmp-*` container runs |
| `retry_set.sh` | reruns, once, the servers whose first pass timed out on the same host; first-pass files move to `raw-firstpass/` |
| `retry_cross.sh` | reruns another host's timeouts on this host into `raw/<set>-retry/` |
| `attested_rest.sh` | the rest of attested's queue after the resume, driven on the host |
| `hub_watchdog_host.sh`, `hub_watchdog_host2.sh` | pause every `warden-cmp-*` container when the attestedmemory hub's local health route is slower than 2 s (median of three) in 3 of 5 minutes |
| `probe.sh` | servers/min and timeouts per scanner and worker count, on 64 servers, output in the container's tmpfs |
| `workers-*.conf` | the worker counts each host used for the package sets |
| `compare.py` | per-server, per-scanner diff of two normalized results (the cross-host and pilot checks) |

`../assemble_hosts.py` merges both hosts' raw outputs into the normalized results, with provenance.
