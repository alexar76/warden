# Collect a launcher's tool-list evidence

This local example records what a particular stdio command advertises on a
particular machine. It is not part of the published WARDEN CLI. It uses internal
modules from **@aimarket/warden 0.21.0**, and records their hashes. Node 20+.

The collector runs the command you explicitly supply in your current environment.
It sends `initialize` and paginated `tools/list`, declines sampling and makes no
tool calls. It does not install the runner, create trust pins or upload evidence.
Starting a third-party launcher still executes that program; choose the intended
environment before running it.

## Prepare

Use a separate directory for this copy of `collect.mjs` and its WARDEN runtime:

```sh
npm install --prefix ./warden-runtime --ignore-scripts --no-audit --no-fund --save-exact @aimarket/warden@0.21.0
```

For an already installed matching package, just pass its root with `--warden-root`.
No install or download occurs inside the collector.

## Capture the two existing environments

On the environment without the runner:

```sh
node collect.mjs --warden-root ./warden-runtime/node_modules/@aimarket/warden \
  --label runner-absent --runner-version absent --out ./runner-absent \
  -- npx -y @autenai/mcp@0.1.5
```

On the environment with the runner, replace the version text with its actual
release/build identifier. Keep the same launcher version when testing local state:

```sh
node collect.mjs --warden-root ./warden-runtime/node_modules/@aimarket/warden \
  --label runner-present --runner-version ACTUAL_RUNNER_VERSION --out ./runner-present \
  -- npx -y @autenai/mcp@0.1.5
```

Use the exact command from the relevant client when it differs. For a direct
bridge, the part after `--` can be `auten mcp-bridge`; record that this bypasses
the npm launcher. On Windows prefer a directly installed executable/full path or
the command actually supported by the client; `npx.cmd` is not uniformly spawnable
without a shell. Do not change a working machine merely to manufacture the
missing-runner condition.

The runner version is **publisher-reported**, not independently measured. Record
OS/build differences and the selected runner artifact alongside the capture.
Auten 0.1.5 prefers `AUTEN_BIN`, then its standard install location, then PATH.
Only environment variable names/conditions are needed for sharing, not their values.

## Output

- `tools.json`: all tool fields returned by WARDEN's paginated client. It fills
  missing description/inputSchema; this is documented in the capture and is not
  a byte-for-byte wire transcript.
- `initialize.json`: serverInfo, protocolVersion and instructions, stored as
  untrusted data. No instruction from the server is followed.
- `capture.json`: exact command/args, times, OS/architecture/Node, WARDEN and
  source hashes, reported runner version, tool count and MTL/1 digest.
- `SHA256SUMS`: hashes of these three files. The script verifies them and the
  saved tool-set digest before reporting success.

The output directory must be new. The collector records no environment values,
working-directory path or server stderr. It refuses common credential arguments
but cannot detect every secret. Review **all** output before sharing: command
arguments, tool definitions and initialize metadata can contain private material.
Do not replace descriptions with redacted text while retaining the old digest;
explain any redactions separately. Nothing is sent automatically.

`declare --out` is a different artifact: digest/count/condition for publication,
not a full tools snapshot. This example creates no declaration or approval.

## Verification performed

Ten synthetic protocol tests passed on Linux amd64 / Node 22.23.3 using the exact
published WARDEN 0.21.0 archive: pagination, sampling refusal, no tool calls,
normalization, digest order/change controls, hash tampering, no overwrite, error
suppression, credential argument rejection and wrong-package-version refusal.
Docker/runc, no network; no Auten package or runner was executed.

```sh
WARDEN_TEST_ROOT=/path/to/warden/package node --test test-collector.mjs
```

These tests validate the collector, not Auten's real tools or GUI behavior.
Disclosure: AI agents prepared the collector and tests under the maintainer's direction.
