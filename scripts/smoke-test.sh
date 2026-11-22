#!/usr/bin/env sh
# Starts an image the way docker-compose.yml runs it (read-only, no
# capabilities, non-root) next to a throwaway PostgreSQL and checks that it
# comes up healthy (GET /api/health), serves the web interface and answers
# the API. Used by
# the Release workflow before an image is published. Needs only Docker.
#
#   scripts/smoke-test.sh IMAGE [EXPECTED_VERSION]
set -eu
IMAGE=${1:?usage: scripts/smoke-test.sh IMAGE [EXPECTED_VERSION]}
WANT=${2:-}
id="driftband-smoke-$$"
cleanup() { docker rm -f "$id-app" "$id-db" >/dev/null 2>&1 || true; docker network rm "$id" >/dev/null 2>&1 || true; }
trap cleanup EXIT INT TERM
fail() { echo "smoke test: $*" >&2; docker logs "$id-app" 2>&1 | tail -n 20 >&2 || true; exit 1; }

got=$(docker run --rm "$IMAGE" --version)
echo "$got"
[ -z "$WANT" ] || [ "$got" = "driftband $WANT" ] || fail "expected version $WANT"
[ "$(docker run --rm --entrypoint id "$IMAGE" -u)" = 10001 ] || fail "the image does not run as uid 10001"

docker network create "$id" >/dev/null
docker run -d --name "$id-db" --network "$id" --network-alias db \
  --tmpfs /var/lib/postgresql:rw,size=256m \
  -e POSTGRES_USER=driftband -e POSTGRES_PASSWORD=smoke -e POSTGRES_DB=driftband \
  postgres:18-alpine >/dev/null
until docker exec "$id-db" pg_isready -q -h 127.0.0.1 -U driftband 2>/dev/null; do sleep 1; done

docker run -d --name "$id-app" --network "$id" \
  --read-only --cap-drop ALL --security-opt no-new-privileges:true \
  --sysctl net.ipv4.ping_group_range="0 2147483647" \
  -e DATABASE_URL="postgres://driftband:smoke@db:5432/driftband?sslmode=disable" \
  "$IMAGE" >/dev/null

i=0
until [ "$(docker inspect -f '{{.State.Health.Status}}' "$id-app" 2>/dev/null)" = healthy ]; do
  i=$((i + 1))
  [ "$i" -lt 90 ] || fail "the container did not become healthy"
  [ "$(docker inspect -f '{{.State.Running}}' "$id-app")" = true ] || fail "the container stopped"
  sleep 1
done

get() { docker exec "$id-app" wget -q -O - "http://127.0.0.1:8080$1" 2>&1; }
get /api/health | grep -q '"status":"ok"' || fail "GET /api/health does not report ok"
get / | grep -q '<title>Driftband</title>' || fail "the web interface is not served"
get /favicon.svg | grep -q '<svg' || fail "static assets are not served"
# without a session the API must refuse, not fall through to the page
get /api/me | grep -q 'server returned error: HTTP/1.1 401' || fail "GET /api/me did not answer 401"
# fping must work without privileges
docker exec "$id-app" fping -C 1 -q 127.0.0.1 >/dev/null 2>&1 || fail "fping cannot send ICMP"

echo "smoke test passed: $IMAGE"
