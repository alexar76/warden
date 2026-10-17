#!/bin/sh
# Inside the container: throughput and timeouts per scanner and worker count, on N servers, output in /tmp.
set -u
python3 -c "import json;c=json.load(open('/work/sets/packages-b-config.json'))['mcpServers'];ks=sorted(c)[-64:];json.dump({'mcpServers':{k:c[k] for k in ks}},open('/tmp/p.json','w'))"
for spec in "mcp-audit 6" "mcp-audit 9" "mcp-audit 12" "truecopy 8" "truecopy 16" "mcpsentry 8" "mcpsentry 12" "mcpsentry 16" "mcp-shield 12" "mcp-shield 24" "mcp-shield 32"; do
  set -- $spec; t=$1; w=$2; o=/tmp/o-$t-$w; rm -rf $o
  s=$(date +%s); python3 /work/harness/run_competitors.py /tmp/p.json $o --installed --only $t --workers $w >/dev/null 2>&1; e=$(date +%s)
  to=$(grep -l -E "timed out|Timed out|TIMEOUT|_error" $o/$t/* 2>/dev/null | wc -l)
  echo "$t workers=$w servers=64 seconds=$((e-s)) per_min=$(( 64*60/(e-s) )) timeouts_or_errors=$to"
  rm -rf $o
done
