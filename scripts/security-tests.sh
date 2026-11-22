#!/usr/bin/env sh
# Runs the backend test suite, including the security tests, against a
# throwaway PostgreSQL in Docker. Needs only Docker. Extra args go to
# `go test` (e.g. -run TestTwoFactor).
#
#   scripts/security-tests.sh
#   scripts/security-tests.sh -run 'TestLogin|TestSession'
set -eu

cd "$(dirname "$0")/.."
id="driftband-sectest-$$"
cleanup() { docker rm -f "$id-db" >/dev/null 2>&1 || true; docker network rm "$id" >/dev/null 2>&1 || true; }
trap cleanup EXIT INT TERM

docker network create "$id" >/dev/null
docker run -d --rm --name "$id-db" --network "$id" \
  -e POSTGRES_PASSWORD=sectest postgres:18-alpine >/dev/null
until docker exec "$id-db" pg_isready -U postgres >/dev/null 2>&1; do sleep 1; done

# fping is installed so a real probe cycle is part of the suite (the test
# skips where fping is missing, e.g. in CI).
docker run --rm --network "$id" \
  -v "$PWD/backend:/src" -w /src \
  -v driftband-gocache:/go \
  -e TEST_DATABASE_URL="postgres://postgres:sectest@$id-db:5432/postgres?sslmode=disable" \
  golang:1.27-alpine \
  sh -c 'apk add --no-cache -q fping >/dev/null 2>&1; exec go test -count=1 "$@" ./...' sh "$@"
