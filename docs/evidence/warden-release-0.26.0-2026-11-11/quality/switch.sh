#!/usr/bin/env bash
# Production HISTOR (82.47.146.138) onto the MOMUS-evaluated image: histor-histor:warden-0.26.0-prod
# (sha256:a1a3ab932a6b…) = the running image plus WARDEN 0.26.0. Only the image line of the override changes.
# Rollback: cp /root/wd026-prod-20261111/docker-compose.warden-image.yml.pre /opt/histor/docker-compose.warden-image.yml
#           and the same `docker compose … up -d --no-deps histor`.
set -euo pipefail
D=/root/wd026-prod-20261111
NEW=sha256:a1a3ab932a6b4adfa8b1e85334824947a61d7d46078d08421535d390f4f93b0a
cd /opt/histor
[ "$(docker image inspect -f '{{.Id}}' histor-histor:warden-0.26.0-prod)" = "$NEW" ]
cp -a docker-compose.warden-image.yml "$D/docker-compose.warden-image.yml.pre"
grep -q 'image: histor-histor:pre-wd-20261111' docker-compose.warden-image.yml
sed -i 's#image: histor-histor:pre-wd-20261111#image: histor-histor:warden-0.26.0-prod#' docker-compose.warden-image.yml
docker compose -p histor -f docker-compose.yml -f docker-compose.postgres.yml -f docker-compose.warden-image.yml up -d --no-deps histor
for i in $(seq 1 60); do
  s="$(docker inspect -f '{{.State.Health.Status}}' histor-histor-1)"
  [ "$s" = healthy ] && break
  sleep 5
done
echo "health=$s image=$(docker inspect -f '{{.Image}}' histor-histor-1)"
[ "$s" = healthy ] && [ "$(docker inspect -f '{{.Image}}' histor-histor-1)" = "$NEW" ]
