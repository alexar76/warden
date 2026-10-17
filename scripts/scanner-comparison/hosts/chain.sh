#!/bin/sh
# chain.sh STEP...   STEP = SET:MODE:CPUS. Runs the steps one at a time. Before each step it waits
# until no warden-cmp-* container runs on this host (one scanner container per host) and until the
# set's READY marker exists (written after its inputs are in the manifest).
W=/opt/warden-cmp/20261016
[ -n "$WAIT_PID" ] && while kill -0 "$WAIT_PID" 2>/dev/null; do sleep 30; done
for step in "$@"; do
  s=${step%%:*}; rest=${step#*:}; mode=${rest%%:*}; cpus=${rest#*:}
  until [ -f $W/sets/$s.READY ]; do sleep 60; done
  while docker ps --format '{{.Names}}' | grep -q '^warden-cmp-'; do sleep 30; done
  sh $W/run_set.sh $s $mode $cpus
done
echo "$(date -u +%FT%TZ) CHAIN-DONE $*"
