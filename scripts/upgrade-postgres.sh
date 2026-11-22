#!/bin/sh
# Moves the Driftband database to the PostgreSQL major version named in
# docker-compose.yml: dumps the running (old) server, starts the new one
# with an empty data directory, restores the dump and compares the row
# counts of every table. Needs only Docker. The application is stopped for
# the duration.
#
#   scripts/upgrade-postgres.sh [dump-file]
#
# Run it after changing the postgres image in docker-compose.yml and BEFORE
# `docker compose up`, while the old database container is still running.
# Nothing is deleted: the old data directory and the dump file stay until
# you remove them.
set -eu
cd "$(dirname "$0")/.."

DUMP=${1:-backups/driftband-$(date +%Y%m%d-%H%M%S).dump}
dc() { docker compose "$@"; }
sql() { dc exec -T db psql -U driftband -d driftband -v ON_ERROR_STOP=1 -Atc "$1"; }
major() { echo $(( $1 / 10000 )); }
# every table of the application with its exact row count
COUNTS="select table_name || ' ' || (xpath('/row/c/text()', query_to_xml(format('select count(*) as c from %I.%I', table_schema, table_name), false, true, '')))[1]::text
        from information_schema.tables where table_schema = 'public' and table_type = 'BASE TABLE' order by 1"

old=$(sql 'show server_version_num') || { echo "the old database container is not running: start it first (docker compose start db)" >&2; exit 2; }
new=$(dc run --rm --no-deps -T --entrypoint postgres db --version 2>/dev/null | sed -n 's/.* \([0-9][0-9]*\)\..*/\1/p')
old=$(major "$old")
[ -n "$new" ] || { echo "cannot read the PostgreSQL version of the db image" >&2; exit 2; }
if [ "$old" -ge "$new" ]; then
  echo "the database already runs PostgreSQL $old: nothing to do"
  exit 0
fi
echo "==> upgrading PostgreSQL $old to $new"

mkdir -p "$(dirname "$DUMP")"
umask 077
echo "==> stopping the application"
dc stop driftband >/dev/null 2>&1 || true

echo "==> dumping the database to $DUMP"
dc exec -T db pg_dump -U driftband -d driftband -Fc > "$DUMP"
before=$(sql "$COUNTS")

echo "==> replacing the database container"
dc stop db >/dev/null 2>&1
dc rm -f db >/dev/null 2>&1
dc up -d db >/dev/null 2>&1
# the image's first start runs a temporary server on the socket only; wait
# for the real one, which also listens on TCP
i=0
until dc exec -T db pg_isready -q -h 127.0.0.1 -U driftband 2>/dev/null; do
  i=$((i + 1))
  [ "$i" -lt 120 ] || { echo "the new database did not start: see docker compose logs db" >&2; exit 1; }
  sleep 1
done
now=$(major "$(sql 'show server_version_num')")
[ "$now" = "$new" ] || { echo "the database container runs PostgreSQL $now, expected $new" >&2; exit 1; }
[ "$(sql "select count(*) from information_schema.tables where table_schema = 'public'")" = 0 ] \
  || { echo "the new database is not empty: refusing to restore over it" >&2; exit 1; }

echo "==> restoring"
dc exec -T db pg_restore -U driftband -d driftband --exit-on-error < "$DUMP"
sql 'analyze' >/dev/null

after=$(sql "$COUNTS")
if [ "$before" != "$after" ]; then
  echo "row counts differ after the restore; the application stays stopped." >&2
  echo "The old data is untouched and the dump is in $DUMP." >&2
  exit 1
fi
echo "==> $(echo "$after" | wc -l | tr -d ' ') tables restored, row counts match"

echo "==> starting the application"
dc up -d >/dev/null 2>&1
echo "done: PostgreSQL $new. The old data directory is still in place; remove"
echo "it and the dump ($DUMP) once you are satisfied."
