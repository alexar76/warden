#!/bin/sh
# Host driver for model.py: relay.py on the host holds the key; AgentDojo runs in gVisor with no network.
# Start it detached, so it outlives the shell that started it:
#   WORK=/root/adojo-model ENV_FILE=/root/x/.env ENV_NAME=DEEPSEEK_API_KEY BUDGET=10 setsid nohup sh run-model.sh >/dev/null 2>&1 &
# WORK/ctx is the image's build context (dist/ + scripts/agentdojo/); results land in WORK/out, logs in WORK/*.log.
# RELAY_EXTRA passes relay.py flags, e.g. another endpoint: RELAY_EXTRA="--url https://openrouter.ai/api/v1/chat/completions --price-miss 0.05 --price-hit 0.05 --price-out 0.08".
# Re-running resumes: model.py skips runs already in WORK/out, relay.py keeps counting spend from WORK/relay/usage.jsonl.
set -u
WORK=${WORK:-/root/adojo-model}
MODEL=${MODEL:-deepseek-flash}
LABEL=${LABEL:-DeepSeek}
IMAGE=${IMAGE:-warden-adojo:model}
mkdir -p "$WORK/relay/req" "$WORK/relay/resp" "$WORK/out"
chown -R 1000:1000 "$WORK/relay" "$WORK/out"
rm -f "$WORK/relay/stop"
python3 "$WORK/ctx/scripts/agentdojo/relay.py" "$WORK/relay" --env-file "$ENV_FILE" --env-name "$ENV_NAME" \
  --model "$MODEL" --budget-usd "$BUDGET" ${RELAY_EXTRA:-} >>"$WORK/relay.log" 2>&1 &
relay=$!
# shellcheck disable=SC2086 -- EXTRA is a list of model.py flags
docker run --rm --name "${NAME:-warden-adojo-model}" --runtime runsc --network none --cpus "${CPUS:-2}" --cpu-shares 256 \
  --memory "${MEM:-4g}" -v "$WORK/relay:/relay" -v "$WORK/out:/out" --entrypoint python3 "$IMAGE" \
  scripts/agentdojo/model.py /out --model "$MODEL" --model-label "$LABEL" --shards "${SHARDS:-8}" ${EXTRA:-} >>"$WORK/run.log" 2>&1
echo "container exit $? at $(date -u +%FT%TZ)" >>"$WORK/run.log"
touch "$WORK/relay/stop"
wait $relay
