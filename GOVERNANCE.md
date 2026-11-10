# Governance — WARDEN

How decisions about WARDEN are made, who makes them, and what a change has to show before it ships.

## Maintainers

WARDEN has one core maintainer today: Aleksandr Artamokhov ([@alexar76](https://github.com/alexar76)). The
maintainer reviews and merges changes, publishes releases to npm, runs the security process in
[SECURITY.md](SECURITY.md), and operates the ERC-8004 feedback described below.

We are looking for a second maintainer; see "Becoming a maintainer".

## How decisions are made

- Proposals arrive as issues or pull requests. The maintainer decides and writes the reason in the issue or pull
  request, including when the answer is no.
- A change to what WARDEN blocks is judged on measurements, not on argument:
  - rules are written from the development half of MCPTox (Wang et al., AAAI 2026) only, and the held-out half is
    measured once, after the rule is frozen;
  - the 45 clean MCPTox servers must stay clean, and the field corpus ([docs/scanner-comparison.md](docs/scanner-comparison.md))
    is re-run to count new false positives;
  - the numbers go into [docs/gates.md](docs/gates.md) and the [CHANGELOG](CHANGELOG.md) with the ruleset version and
    digest. A rule that blocks a clean server is not merged.
- Every number the README states must be reproducible from a script in this repository (`scripts/scanner-comparison`,
  `scripts/agentdojo`, `scripts/redteam`). Attacks that still get through are published along with the ones we stop.
- Runtime dependencies stay at zero (see [CONTRIBUTING.md](CONTRIBUTING.md)).

## Releases

- One published version means exactly one rule table: `STATIC_SCAN_RULESET_VERSION` and its digest.
  `npm run check:ruleset` fails when the docs and the bundled table disagree.
- `npm publish` runs `prepublishOnly`: build, tests, the red-team suite, `check:ruleset` and `check:quality`.
- `check:quality` accepts only release evidence signed by an independent evaluator (the MOMUS release gate) for this
  exact build digest, under the policy `zero-regressions-v1`, at most 48 hours old. A pull-request runner cannot sign it.
- The release candidate also runs in HISTOR's production scanner; the maintainer publishes to npm.
- Releases are batched. Fixes land under `## Unreleased` in the CHANGELOG and ship together, at most about once a
  week; a security fix for a reported bypass may ship on its own. Three npm versions in four days (0.23.0 → 0.25.0)
  left docs and an operator's install instructions naming a version that never came out.
- Docs name only released versions. Before a release, write "the next release", not a number: a number is promised
  only once its `## X.Y.Z — date` heading is in the CHANGELOG. `npm run check:versions` (also part of `npm test`)
  fails on a reference to an unreleased or development version; `prepublishOnly` additionally requires every install
  pin (README, plugin, Action, pre-commit, examples) to equal the version being published.

## Security

Reports go privately to the address in [SECURITY.md](SECURITY.md): acknowledgement within 72 hours, up to 90 days of
coordinated disclosure, credit on request. A fix for a reported bypass ships with a regression test. Known bypasses
from our own red team are listed in the docs instead of being kept quiet.

## Public feedback on other agents

WARDEN's operator posts the results of weekly scans of ERC-8004 agents on Base to the ERC-8004 Reputation Registry.
The rules:

- no feedback on agents we own or operate;
- a scan with a blocking finding is held for a person to review and is not posted as a negative mark;
- a feedback is revoked when a later scan changes the verdict, and re-issued when the scanner release changes;
- each feedback points to a public report and commits to its hash, so anyone can check what was scanned and when.

## Becoming a maintainer

Sustained contribution earns maintainer rights: several merged pull requests, including at least one rule change
with its measurements or one security fix, and agreement to follow the security process. The current maintainer
adds new maintainers and lists them here.

Once there are two or more maintainers, every release needs a second maintainer to review the diff since the
previous release.

## Changing this document

Through a pull request, approved by a maintainer.
