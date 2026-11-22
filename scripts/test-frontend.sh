#!/usr/bin/env sh
# Frontend stage: the Playwright suite in tests/e2e (module tests in the
# browser, end-to-end flows through the UI and browser-side security checks)
# against the throwaway stack from scripts/test-stack.sh.
# Needs only Docker. Output goes to the directory given as $1 (default:
# ./reports/e2e); the stack's credentials are read from $1/../stack.env
# unless STACK_ENV points elsewhere. Extra arguments go to `playwright test`
# (e.g. --grep "@security", specs/auth.spec.js).
#
#   scripts/test-stack.sh up reports/run
#   scripts/test-frontend.sh reports/run/e2e
#
# E2E_EXTRA_SPECS names a directory with more spec files (for example the
# tests of your own deployment); they run with the suite as specs/extra/.
set -eu
cd "$(dirname "$0")/.."
OUT=${1:-reports/e2e}
[ $# -gt 0 ] && shift
mkdir -p "$OUT"
OUT=$(cd "$OUT" && pwd)
ENV_FILE=${STACK_ENV:-$OUT/../stack.env}
[ -f "$ENV_FILE" ] || { echo "no $ENV_FILE: start the stack first (scripts/test-stack.sh up DIR)" >&2; exit 2; }

PW_VERSION=$(sed -n 's/.*"@playwright\/test": *"\([0-9.]*\)".*/\1/p' tests/e2e/package.json)
PW_IMAGE="mcr.microsoft.com/playwright:v${PW_VERSION}-noble"

# Dependencies live in a named volume mounted over tests/e2e/node_modules,
# so nothing is installed on the host. The container runs as the host user
# so the report files are owned by it (the volume is handed over first).
docker run --rm -v driftband-e2e-modules:/m "$PW_IMAGE" chown "$(id -u):$(id -g)" /m
docker run --rm --network driftband-test --ipc=host --init \
  --user "$(id -u):$(id -g)" -e HOME=/tmp/home -e npm_config_cache=/tmp/npm-cache \
  -v "$PWD/tests/e2e:/work" -v driftband-e2e-modules:/work/node_modules -v "$OUT:/work/out" \
  ${E2E_EXTRA_SPECS:+-v "$(cd "$E2E_EXTRA_SPECS" && pwd):/work/specs/extra:ro"} \
  --env-file "$ENV_FILE" -e PLAYWRIGHT_OUT=/work/out -w /work "$PW_IMAGE" sh -c '
    set -e
    mkdir -p "$HOME"
    if [ ! -x node_modules/.bin/playwright ] || [ "$(node -p "require(\"@playwright/test/package.json\").version")" != "'"$PW_VERSION"'" ]; then
      echo "==> installing test dependencies"
      if [ -f package-lock.json ]; then npm ci --no-audit --no-fund --loglevel=error; else npm install --no-audit --no-fund --loglevel=error; fi
    fi
    npx playwright test "$@"' sh "$@"
