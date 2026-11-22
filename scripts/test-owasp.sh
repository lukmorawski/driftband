#!/usr/bin/env sh
# OWASP stage: OWASP ZAP against the throwaway stack from
# scripts/test-stack.sh, signed in as the scanner's own organization.
#
#   scripts/test-owasp.sh [outdir]            # baseline: crawl + passive rules
#   scripts/test-owasp.sh [outdir] --active   # plus the active scan (slow)
#
# The baseline crawls the application (classic and AJAX spider) and checks every
# response against ZAP's passive rules. The active scan additionally attacks
# every parameter it found (injection, traversal and so on); it takes long
# and is run on request. Output: ZAP's HTML, Markdown and JSON reports in
# outdir, plus zap.log. tests/owasp/zap.conf decides which rules fail the
# stage, warn, or are ignored (with the reason next to each ignore).
#
# Exit status: ZAP's own: 0 pass, 1 a FAIL rule triggered, 2 only warnings.
set -eu
cd "$(dirname "$0")/.."
OUT=${1:-reports/owasp}
[ $# -gt 0 ] && shift
mkdir -p "$OUT"
OUT=$(cd "$OUT" && pwd)
ENV_FILE=${STACK_ENV:-$OUT/../stack.env}
[ -f "$ENV_FILE" ] || { echo "no $ENV_FILE: start the stack first (scripts/test-stack.sh up DIR)" >&2; exit 2; }
# shellcheck disable=SC1090
. "$ENV_FILE"
mode=baseline
for a in "$@"; do [ "$a" = "--active" ] && mode=full; done

cookie=$(scripts/test-stack.sh login "$ZAP_EMAIL" "$ZAP_PASSWORD")
[ -n "$cookie" ] || { echo "could not sign in as $ZAP_EMAIL" >&2; exit 2; }

# The session cookie is injected into every request (replacer). Signing out
# is excluded from the crawl, otherwise the spider would end its own session.
# ZAP sizes its Java heap at a quarter of the machine's memory and drives
# several browsers for the client spider. On a small VM that sits next to
# the stack under test, a fixed heap and one browser keep the scan within
# memory; the site is small, so neither slows it down noticeably.
zapopts="-Xmx512m -config ajaxSpider.numberOfBrowsers=1 \
  -config replacer.full_list(0).description=session \
  -config replacer.full_list(0).enabled=true \
  -config replacer.full_list(0).matchtype=REQ_HEADER \
  -config replacer.full_list(0).matchstr=Cookie \
  -config replacer.full_list(0).regex=false \
  -config replacer.full_list(0).replacement=dband_session=$cookie \
  -config network.globalExclusions.exclusions.exclusion(0).name=logout \
  -config network.globalExclusions.exclusions.exclusion(0).value=.*/api/auth/logout.* \
  -config network.globalExclusions.exclusions.exclusion(0).enabled=true"

zap() {
  docker run --rm --network driftband-test --memory 2g --user "$(id -u):$(id -g)" \
    -v "$OUT:/zap/wrk:rw" ghcr.io/zaproxy/zaproxy:stable "$@"
}
cp tests/owasp/zap.conf "$OUT/zap.conf"
cp tests/owasp/openapi.yaml "$OUT/openapi.yaml"
sed -i "s|url: http://sut:8080|url: $BASE_URL|" "$OUT/openapi.yaml"

# 1. The application as a browser sees it: crawl (classic
#    and client spider) and the passive rules; --active adds the active scan.
script=zap-baseline.py
[ "$mode" = full ] && script=zap-full-scan.py
echo "==> ZAP $mode scan of $BASE_URL (signed in as $ZAP_EMAIL)"
set +e
zap "$script" -t "$BASE_URL" -j -c zap.conf -r zap-report.html -w zap-report.md -J zap-report.json \
  -z "$zapopts" > "$OUT/zap.log" 2>&1
rc=$?
set -e
grep -E '^(FAIL-NEW: |Total of)' "$OUT/zap.log" || tail -n 20 "$OUT/zap.log"

# 2. The JSON API from its OpenAPI description (tests/owasp/openapi.yaml):
#    every route and parameter gets ZAP's active API rules (injection,
#    traversal, malformed input), signed in as the scanner's organization.
echo "==> ZAP API scan of $BASE_URL/api (tests/owasp/openapi.yaml)"
set +e
zap zap-api-scan.py -t openapi.yaml -f openapi -c zap.conf -r zap-api-report.html -w zap-api-report.md -J zap-api-report.json \
  -z "$zapopts" > "$OUT/zap-api.log" 2>&1
rc2=$?
set -e
grep -E '^(FAIL-NEW: |Total of)' "$OUT/zap-api.log" || tail -n 20 "$OUT/zap-api.log"

# worst of the two: 1 (a FAIL rule) beats 2 (warnings) beats 0
if [ "$rc" -eq 1 ] || [ "$rc2" -eq 1 ]; then exit 1; fi
if [ "$rc" -eq 2 ] || [ "$rc2" -eq 2 ]; then exit 2; fi
exit $((rc > rc2 ? rc : rc2))
