#!/usr/bin/env sh
# Throwaway Driftband stack for the browser and OWASP tests: the image built
# from this checkout, a PostgreSQL kept in memory, and nothing published on
# the host. Test tools join the "driftband-test" network and
# reach the application at http://sut:8080 ("sut": system under test; the
# name must not be a public suffix such as "app", which browsers force to HTTPS).
# Security keys and passkeys need a secure context and a host name of two
# labels or more: the application is told its address is
# http://driftband.localhost:8080 (APP_URL), which browsers treat as secure;
# the container answers to that name on the test network (for the test
# runner), and the browser, which resolves *.localhost to itself, is pointed
# at the container in tests/e2e/playwright.config.js.
#
#   scripts/test-stack.sh up [dir]   # build, start, seed accounts; writes dir/stack.env
#   scripts/test-stack.sh down
#   scripts/test-stack.sh logs
#
# The stack is seeded with a platform administrator and a plain organization
# for the OWASP scanner; their credentials land in stack.env (mode 600).
#
# TEST_IMAGE names the image (default driftband:test); with TEST_BUILD=no it
# is used as it is instead of being built from the checkout.
set -eu
cd "$(dirname "$0")/.."

NET=driftband-test
APP=driftband-test-app
DB=driftband-test-db
IMAGE=${TEST_IMAGE:-driftband:test}

random() { od -An -N"${1:-16}" -tx1 /dev/urandom | tr -d ' \n'; }

# post PATH JSON: a request from inside the app container (busybox wget),
# headers on stderr, body on stdout.
post() { docker exec "$APP" wget -q -S -O - --header 'Content-Type: application/json' --post-data "$2" "http://127.0.0.1:8080$1"; }

down() {
  docker rm -f "$APP" "$DB" >/dev/null 2>&1 || true
  docker network rm "$NET" >/dev/null 2>&1 || true
}

up() {
  dir=${1:-.}
  mkdir -p "$dir"
  down
  if [ "${TEST_BUILD:-yes}" != no ]; then
    echo "==> building $IMAGE"
    docker build -q -t "$IMAGE" . >/dev/null
  fi
  docker network create "$NET" >/dev/null
  docker run -d --name "$DB" --network "$NET" --network-alias db \
    --tmpfs /var/lib/postgresql:rw,size=768m \
    -e POSTGRES_USER=driftband -e POSTGRES_PASSWORD=stacktest -e POSTGRES_DB=driftband \
    postgres:18-alpine >/dev/null
  until docker exec "$DB" pg_isready -U driftband >/dev/null 2>&1; do sleep 1; done

  # Same hardening as docker-compose.yml, so the tests exercise the image the
  # way it is deployed.
  docker run -d --name "$APP" --network "$NET" --network-alias sut --network-alias driftband.localhost \
    --read-only --cap-drop ALL --security-opt no-new-privileges:true \
    --sysctl net.ipv4.ping_group_range="0 2147483647" \
    -e DATABASE_URL="postgres://driftband:stacktest@db:5432/driftband?sslmode=disable" \
    -e LISTEN=:8080 -e SECRET_KEY="$(random 32)" -e APP_URL=http://driftband.localhost:8080 -e TEST_INSTANCE=no \
    "$IMAGE" >/dev/null
  i=0
  until docker exec "$APP" wget -q -O /dev/null http://127.0.0.1:8080/api/health 2>/dev/null; do
    i=$((i + 1))
    [ "$i" -lt 60 ] || { echo "the application did not start" >&2; docker logs "$APP" >&2; exit 1; }
    sleep 1
  done

  # Seed: a platform administrator (flag set directly in the database, as in
  # production) and an ordinary organization for the scanner.
  SA_EMAIL="platform-admin@e2e.test"; SA_PASS="Pa-$(random 12)"
  ZAP_EMAIL="owasp-owner@e2e.test"; ZAP_PASS="Za-$(random 12)"
  post /api/auth/register-org "{\"org_name\":\"Platform\",\"email\":\"$SA_EMAIL\",\"password\":\"$SA_PASS\"}" >/dev/null 2>&1
  post /api/auth/register-org "{\"org_name\":\"OWASP scan\",\"email\":\"$ZAP_EMAIL\",\"password\":\"$ZAP_PASS\"}" >/dev/null 2>&1
  docker exec "$DB" psql -U driftband -q -c "UPDATE users SET is_superadmin = true WHERE email = '$SA_EMAIL'"
  umask 077
  cat > "$dir/stack.env" <<EOF
BASE_URL=http://sut:8080
WEBAUTHN_URL=http://driftband.localhost:8080
SUPERADMIN_EMAIL=$SA_EMAIL
SUPERADMIN_PASSWORD=$SA_PASS
ZAP_EMAIL=$ZAP_EMAIL
ZAP_PASSWORD=$ZAP_PASS
EOF
  echo "==> stack is up: $APP, $DB on network $NET (credentials in $dir/stack.env)"
}

# login EMAIL PASSWORD: prints a session cookie value for that account.
login() {
  post /api/auth/login "{\"email\":\"$1\",\"password\":\"$2\"}" 2>&1 >/dev/null \
    | sed -n 's/.*Set-Cookie: dband_session=\([^;]*\).*/\1/p' | head -n 1
}

case ${1:-} in
  up) up "${2:-.}" ;;
  down) down ;;
  logs) docker logs "$APP" ;;
  login) login "$2" "$3" ;;
  *) echo "usage: $0 up [dir] | down | logs | login EMAIL PASSWORD" >&2; exit 2 ;;
esac
