#!/bin/sh
# The rest of attested's queue, driven on the host: one container at a time.
W=/opt/warden-cmp/20261016
while docker ps -a --format '{{.Names}}' | grep -q '^warden-cmp-'; do sleep 30; done
sh $W/chain.sh packages-b:resume:2 packages-b:warden:2 packages-xhost:competitors:2 packages-xhost:warden:2
sh $W/retry_set.sh corpus 2
sh $W/retry_set.sh mcptox-decorated 2
echo "$(date -u +%FT%TZ) ALL-DONE attested"
