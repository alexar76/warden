#!/bin/sh
# Run one set in one fresh container from the built image, under the fixed flags.
#   run_set.sh SET competitors|warden|resume CPUS
# raw/SET must not exist yet (fresh state), except for `resume`: the competitor phases continue in a
# fresh container after a pause, and run_competitors.py runs only the servers that have no raw file.
# The log line records start, end and exit.
W=/opt/warden-cmp/20261016; s=$1; mode=$2; cpus=$3
# An operator cap (cpus.cap) overrides the queued value, e.g. when the host's own services need room.
[ -f $W/cpus.cap ] && cpus=$(cat $W/cpus.cap)
# cpu.shares, when present, lowers this container's weight under contention (the host's own services first).
shares=""; [ -f $W/cpu.shares ] && shares="--cpu-shares $(cat $W/cpu.shares)"
# Parallel servers per scanner; workers.conf lowers them on a host where a scanner's own fixed
# connect timeout (mcp-audit: 10 s) is otherwise missed under load.
AUDIT_W=6; TC_W=8; MS_W=8; SH_W=12; [ -f $W/workers.conf ] && . $W/workers.conf
FLAGS="--rm --runtime=runsc --network none --cpus $cpus $shares --memory 2g --memory-swap 2g --pids-limit 512 --read-only --tmpfs /tmp:size=512m -v $W:/work"
if [ "$mode" = warden ]; then out=$W/raw/$s-warden; else out=$W/raw/$s; fi
if [ "$mode" != resume ] && [ -e "$out" ]; then echo "$(date -u +%FT%TZ) REFUSE $s $mode: $out exists"; exit 1; fi
mkdir -p "$out" && chown 1000:1000 "$out"
logf="$out.stdout"; [ "$mode" = resume ] && logf="$out.resume-$(date -u +%H%M%S).stdout"
echo "$(date -u +%FT%TZ) start $s $mode cpus=$cpus $shares workers=$AUDIT_W/$TC_W/$MS_W/$SH_W"
if [ "$mode" = warden ]; then
  docker run $FLAGS --name warden-cmp-$s-warden warden-run:20261016 \
    warden-mcp scan /work/sets/$s-config.json --json-file /work/raw/$s-warden/warden-0.16.0.json --concurrency 4 --no-color > "$out.stdout" 2>&1
else
  docker run $FLAGS --name warden-cmp-$s warden-cmp:20261016 sh -c "
    python3 /work/harness/run_competitors.py /work/sets/$s-config.json /work/raw/$s --installed --only mcp-audit --workers $AUDIT_W
    python3 /work/harness/run_competitors.py /work/sets/$s-config.json /work/raw/$s --installed --only truecopy --workers $TC_W
    python3 /work/harness/run_competitors.py /work/sets/$s-config.json /work/raw/$s --installed --only mcpsentry --workers $MS_W
    python3 /work/harness/run_competitors.py /work/sets/$s-config.json /work/raw/$s --installed --only mcp-shield --workers $SH_W" > "$logf" 2>&1
fi
echo "$(date -u +%FT%TZ) done $s $mode exit=$?"
