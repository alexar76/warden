#!/usr/bin/env bash
# The step behind action.yml. Inputs arrive as environment variables, never spliced into the
# script, so a workflow input cannot become shell code.
set -euo pipefail

fail() { echo "::error title=WARDEN::$1"; exit 2; }
[[ "${WARDEN_VERSION:-}" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || fail "version must look like 1.2.3"
[[ "${WARDEN_FAIL_ON:-high}" =~ ^(info|low|medium|high|critical)$ ]] || fail "fail-on must be info, low, medium, high or critical"
command -v node >/dev/null || fail "WARDEN needs Node 20 or later on the runner (actions/setup-node)"
major="$(node -p 'process.versions.node.split(".")[0]')"
(( major >= 20 )) || fail "WARDEN needs Node 20 or later; the runner has $(node --version)"

tmp="${RUNNER_TEMP:-$(mktemp -d)}"
summary="$tmp/warden-summary.md"
report="$tmp/warden-report.json"
args=(scan --no-color --markdown "$summary" --json-file "$report" --fail-on "${WARDEN_FAIL_ON:-high}")

configs=()
if [[ -n "${WARDEN_CONFIG:-}" ]]; then
  while IFS= read -r line; do
    line="${line#"${line%%[![:space:]]*}"}"; line="${line%"${line##*[![:space:]]}"}"
    [[ -n "$line" ]] && configs+=("$line")
  done <<< "$WARDEN_CONFIG"
fi
if (( ${#configs[@]} == 0 )); then args+=(--project); fi
[[ "${WARDEN_LAUNCH_STDIO:-false}" == "true" ]] || args+=(--no-launch)
[[ "${WARDEN_PUBLIC_ONLY:-true}" == "true" ]] && args+=(--public-only)
[[ "${WARDEN_HISTOR:-false}" == "true" ]] && args+=(--histor)
if [[ -n "${WARDEN_LOCK:-}" && -f "$WARDEN_LOCK" ]]; then args+=(--lock "$WARDEN_LOCK"); fi
sarif=""
if [[ -n "${WARDEN_SARIF:-}" ]]; then sarif="$WARDEN_SARIF"; args+=(--sarif "$sarif"); fi
if [[ -n "${WARDEN_CLASSIFIER_URL_INPUT:-}" || -n "${WARDEN_CLASSIFIER_MODEL_INPUT:-}" ]]; then
  [[ -n "${WARDEN_CLASSIFIER_URL_INPUT:-}" && -n "${WARDEN_CLASSIFIER_MODEL_INPUT:-}" ]] || fail "classifier-url and classifier-model go together"
  args+=(--classifier-url "$WARDEN_CLASSIFIER_URL_INPUT" --classifier-model "$WARDEN_CLASSIFIER_MODEL_INPUT")
  [[ "${WARDEN_CLASSIFIER_BLOCKS:-false}" == "true" ]] && args+=(--classifier-blocks)
fi

# WARDEN_BIN runs a local build instead of the registry package (used by WARDEN's own tests).
if [[ -n "${WARDEN_BIN:-}" ]]; then cmd=(node "$WARDEN_BIN"); else cmd=(npx --yes "@aimarket/warden@$WARDEN_VERSION"); fi

set +e
"${cmd[@]}" "${args[@]}" ${configs[@]+"${configs[@]}"}
code=$?
set -e

[[ -f "$summary" && -n "${GITHUB_STEP_SUMMARY:-}" ]] && cat "$summary" >> "$GITHUB_STEP_SUMMARY"
blocked=0; servers=0
if [[ -f "$report" ]]; then
  blocked="$(node -e 'const r=JSON.parse(require("fs").readFileSync(process.argv[1],"utf8"));process.stdout.write(String(r.summary.blocked))' "$report")"
  servers="$(node -e 'const r=JSON.parse(require("fs").readFileSync(process.argv[1],"utf8"));process.stdout.write(String(r.summary.servers))' "$report")"
fi
if [[ -n "${GITHUB_OUTPUT:-}" ]]; then
  { echo "blocked=$blocked"; echo "servers=$servers"; [[ -n "$sarif" && -f "$sarif" ]] && echo "sarif=$sarif" || echo "sarif="; } >> "$GITHUB_OUTPUT"
fi
(( code == 1 )) && echo "::error title=WARDEN::$blocked MCP server(s) blocked. See the job summary."
exit "$code"
