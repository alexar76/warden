#!/bin/sh
# On attested: every minute 3 requests to the hub's local health route, median latency (non-200 = 99 s).
# If the median is over 2 s in 3 of the last 5 minutes, pause every warden-cmp-* container and stop.
# Ends by itself when the chain log contains the marker given as $1.
W=/opt/warden-cmp/20261016; LOG=$W/hub-watchdog.log; END="$1"; hist=""
while ! grep -q "$END" $W/chain.log 2>/dev/null; do
  m=$(for i in 1 2 3; do r=$(curl -s -o /dev/null -w "%{http_code} %{time_total}" -m 15 http://127.0.0.1:9084/ai-market/v2/health); c=${r% *}; t=${r#* }; [ "$c" = 200 ] && echo "$t" || echo 99; done | sort -n | sed -n 2p)
  slow=$(awk -v m="$m" 'BEGIN{print (m>2)?1:0}'); hist=$(echo "$hist $slow" | awk '{s=""; for(i=(NF>5?NF-4:1);i<=NF;i++) s=s" "$i; print s}')
  bad=$(echo "$hist" | tr ' ' '\n' | grep -c '^1$')
  echo "$(date -u +%FT%TZ) median=${m}s last5=[$hist ] slow=$bad" >> $LOG
  if [ "$bad" -ge 3 ]; then
    for c in $(docker ps --format '{{.Names}}' | grep '^warden-cmp-'); do docker pause $c; done
    echo "$(date -u +%FT%TZ) PAUSED warden-cmp-*: hub median >2 s in $bad of the last 5 minutes" | tee -a $LOG >> $W/chain.log; exit 0
  fi
  sleep 45
done
