# WARDEN 0.26.0 — prepared 2026-11-11, not published

Prepared from aicom `main` at `345bb3880` plus this commit; re-prepared after `projectRoots` (TONM-13 field false positive) joined 0.26.0. The maintainer publishes; nothing here publishes.

**Why 0.26.0.** The core no longer names Multica: `multica issue …` output counts as outside text only with the
preset `examples/policies/multica.flow-policy.json`. That changes a default, so a minor release with an upgrade note
in the CHANGELOG rather than a patch release.

## Artifact

| | |
|---|---|
| Tarball | `aimarket-warden-0.26.0.tgz` (this folder) |
| sha256 | `ff8e9fc959caf1ec2184592bb4cde9ea34d475ea42ce0b380c803afe97331f6b` |
| npm shasum | `12170b8b0c5003674b2ed4e211c977e52a72166e` |
| integrity | `sha512-ANwHhvYBKRcI29I6tx/ahmKtBsnedWxNlJB6+09qkKQqTmU4m04eKnFbXVTmC2zd4Y1R1+HxNWTCnis/by3F/g==` |
| Files / size | 404 files, 1,102,405 bytes packed, 3,706,340 unpacked |
| dist digest | `67871ab10770b6c5d9c9c2bbd12a56a1a12ef7d162c90d315988b8c2e380e59a` |
| Ruleset | v19 `sha256-XfRh1+VZoAM6PGtbmqprnSX/eF16qNYOk0o+ilRFxXw=` (unchanged from 0.25.0) |

## Checks

| Check | Result | Log |
|---|---|---|
| Build, typecheck | pass | `build.log`, `typecheck.log` |
| Tests | 1653 of 1653 with `--maxWorkers=4`. With default workers, process-restart tests (`persistent-pins`, `wrap`) timed out at 5 s under a host load average of 10–34 from other sessions; both files pass alone (125 of 125). | `tests.log` |
| Red team, Claude Code profile | 0 of 28 delivered, 2 answer-only noted; field regressions 0 of 4 | `redteam.log` |
| Red team, Codex / OpenCode | `all`: 0 of 28; `data`: 3 of 28 (the same three action-only attacks as before); field 0 of 4 in every profile | `redteam-*.log` |
| Ruleset vs docs | pass; 0.26.0 not yet on the registry | `ruleset.log` |
| Version references, release mode | pass: every install pin is 0.26.0 | `versions.log` |
| Clean consumer | tarball installs into an empty project; `@aimarket/warden`, `/codex`, `/opencode` import; `warden-mcp --help`; preset, `flow-log-stats.mjs`, fixed-job-runner docs, codex-hooks present; no `multica` in the core classifier | `clean-consumer.log` |
| Scan demo | real output of this tarball, identical to the README block | `scan-demo.log` |
| Quality gate (MOMUS) | **blocked here**: "Quality service unavailable". `prepublishOnly` requires the independent evaluator's signed evidence for this build. | `quality.log` |

## To publish (maintainer)

1. Obtain the MOMUS signature for this build (`npm run check:quality` must pass).
2. From a clean checkout of the release commit: `cd warden && npm ci && npm publish` (runs `prepublishOnly`: build,
   tests, red team, ruleset, quality, release version check).
3. Verify the registry against this folder: `npm view @aimarket/warden@0.26.0 dist.shasum dist.integrity dist.fileCount`
   must equal the npm shasum, integrity and 404 above. Record the result here.
