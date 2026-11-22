#!/usr/bin/env sh
# The whole test suite, run on request. Needs only Docker.
#
#   scripts/test-all.sh                 # everything but the slow active scan
#   scripts/test-all.sh --active        # with ZAP's active scan (adds 15-60 min)
#   scripts/test-all.sh --only frontend # one stage: backend, supply, frontend, owasp
#   scripts/test-all.sh --skip owasp    # all but one stage (repeatable)
#
# Stages, in order (see TESTING.md):
#   backend   gofmt, go vet, the Go test suite with coverage (security matrix
#             included), gosec, govulncheck
#   supply    trivy on the image and the repository, gitleaks on the history
#   frontend  Playwright: module tests in the browser, end-to-end flows,
#             browser-side security checks
#   owasp     OWASP ZAP baseline (crawl + passive rules), signed in; with
#             --active also the active scan
#
# Every run writes reports/<timestamp>/REPORT.md with one line per stage
# and the details next to it (logs, coverage, ZAP and trivy reports, traces
# of failed browser tests). reports/latest points at the newest run.
# Exit status: 0 when every stage passed (warnings do not fail the run).
#
# TEST_IMAGE names the image under test (default driftband:test); with
# TEST_BUILD=no it is used as it is instead of being built from the checkout.
set -u
cd "$(dirname "$0")/.."
IMAGE=${TEST_IMAGE:-driftband:test}

active=""
only=""
skip=" "
while [ $# -gt 0 ]; do
  case $1 in
    --active) active="--active" ;;
    --only) only=$2; shift ;;
    --skip) skip="$skip$2 "; shift ;;
    *) echo "unknown option $1" >&2; exit 2 ;;
  esac
  shift
done
want() { [ -z "$only" ] && [ "${skip#* $1 }" = "$skip" ] || [ "$only" = "$1" ]; }

RUN=reports/$(date -u +%Y%m%d-%H%M%S)
mkdir -p "$RUN"
ln -sfn "$(basename "$RUN")" reports/latest
REPORT=$RUN/REPORT.md
start=$(date +%s)
failed=0
rows=""

# stage NAME COMMAND...: runs the stage, records PASS/WARN/FAIL and a summary.
stage() {
  name=$1; shift
  t0=$(date +%s)
  echo
  echo "=========== $name ==========="
  "$@" > "$RUN/$name.log" 2>&1
  rc=$?
  cat "$RUN/$name.log" | grep -vE '^\s*$' | tail -n 25
  case $rc in
    0) st=PASS ;;
    2) st=WARN ;;
    *) st=FAIL; failed=1 ;;
  esac
  rows="$rows| $name | $st | $(( $(date +%s) - t0 )) s | $(summary "$name") |
"
}

summary() {
  case $1 in
    backend)
      t=$RUN/backend/test.txt
      printf '%s tests passed, %s failed, coverage %s; gosec %s; govulncheck %s' \
        "$(grep -c '^--- PASS' "$t" 2>/dev/null)" "$(grep -c '^--- FAIL' "$t" 2>/dev/null)" \
        "$(tail -n 1 "$RUN/backend/coverage.txt" 2>/dev/null | awk '{print $NF}')" \
        "$(head -n 1 "$RUN/backend/gosec.txt" 2>/dev/null)" \
        "$(grep -qE '^No vulnerabilities found' "$RUN/backend/govulncheck.txt" 2>/dev/null && echo clean || grep -cE '^Vulnerability #' "$RUN/backend/govulncheck.txt" 2>/dev/null | sed 's/$/ findings/')" ;;
    supply)
      tr '\n' ';' < "$RUN/supply/trivy-summary.txt" 2>/dev/null | sed 's/  */ /g; s/;$//'; printf '; gitleaks: %s' "$(grep -q '^ok' "$RUN/supply.log" && echo clean || echo leaks)" ;;
    frontend)
      python3 - "$RUN/e2e/results.json" <<'EOF' 2>/dev/null || echo "no results.json"
import json, sys
d = json.load(open(sys.argv[1]))
s = d.get("stats", {})
print(f"{s.get('expected', 0)} passed, {s.get('unexpected', 0)} failed, {s.get('skipped', 0)} skipped, {s.get('flaky', 0)} flaky")
EOF
      ;;
    owasp)
      printf 'site: %s; API: %s' \
        "$(grep -oE 'FAIL-NEW: [0-9]+|WARN-NEW: [0-9]+|PASS: [0-9]+' "$RUN/owasp/zap.log" 2>/dev/null | tr '\n' ' ')" \
        "$(grep -oE 'FAIL-NEW: [0-9]+|WARN-NEW: [0-9]+|PASS: [0-9]+' "$RUN/owasp/zap-api.log" 2>/dev/null | tr '\n' ' ')" ;;
  esac
}

# The image under test is built once, from this checkout, for the supply
# chain scan and the throwaway stack alike.
if want supply || want frontend || want owasp; then
  echo "=========== image ==========="
  if [ "${TEST_BUILD:-yes}" = no ]; then
    docker image inspect "$IMAGE" > /dev/null 2>&1 || { echo "no image $IMAGE"; exit 1; }
    echo "$IMAGE (not rebuilt)"
  elif docker build -q -t "$IMAGE" . > "$RUN/build.log" 2>&1; then
    echo "$IMAGE built"
  else
    cat "$RUN/build.log"; echo "the image does not build"; exit 1
  fi
fi

want backend && stage backend scripts/test-backend.sh "$RUN/backend"
want supply && stage supply scripts/test-supply-chain.sh "$RUN/supply" "$IMAGE"
if want frontend || want owasp; then
  echo
  echo "=========== test stack ==========="
  if scripts/test-stack.sh up "$RUN" > "$RUN/stack.log" 2>&1; then
    tail -n 1 "$RUN/stack.log"
    want frontend && stage frontend scripts/test-frontend.sh "$RUN/e2e"
    want owasp && stage owasp scripts/test-owasp.sh "$RUN/owasp" $active
    docker logs driftband-test-app > "$RUN/app.log" 2>&1
    scripts/test-stack.sh down
  else
    cat "$RUN/stack.log"; failed=1
    rows="$rows| stack | FAIL | - | the throwaway stack did not start |
"
  fi
fi

{
  echo "# Driftband test report"
  echo
  echo "Run: $(basename "$RUN") (UTC), commit $(git rev-parse --short HEAD 2>/dev/null)$( [ -n "$(git status --porcelain 2>/dev/null)" ] && echo ' with uncommitted changes'), $(( $(date +%s) - start )) s"
  echo
  echo "| Stage | Result | Time | Summary |"
  echo "|---|---|---|---|"
  printf '%s' "$rows"
  echo
  echo "PASS: nothing to do. WARN: findings to review (details below). FAIL: must be fixed or justified."
  echo
  if [ -f "$RUN/backend/coverage.txt" ]; then
    echo "## Backend"
    echo
    echo "Functions without any test coverage (go tool cover):"
    echo
    echo '```'
    awk '$NF == "0.0%" {print $1, $2}' "$RUN/backend/coverage.txt" | sed 's|^driftband/||' | sort
    echo '```'
    echo
    if [ -s "$RUN/backend/gosec.txt" ]; then echo "gosec:"; echo; echo '```'; cat "$RUN/backend/gosec.txt"; echo '```'; echo; fi
    if [ -f "$RUN/backend/govulncheck.txt" ]; then echo "govulncheck:"; echo; echo '```'; grep -vE '^(Scanning|Fetching|Checking)' "$RUN/backend/govulncheck.txt" | head -n 40; echo '```'; echo; fi
  fi
  if [ -f "$RUN/supply/trivy-summary.txt" ]; then
    echo "## Supply chain"; echo; echo '```'; cat "$RUN/supply/trivy-summary.txt"; echo '```'; echo
  fi
  if [ -f "$RUN/e2e/results.json" ]; then
    echo "## Frontend"; echo
    python3 - "$RUN/e2e/results.json" <<'EOF'
import json, re, sys
d = json.load(open(sys.argv[1]))
plain = lambda s: re.sub(r"\x1b\[[0-9;]*m", "", s)
def walk(suites, path=""):
    for s in suites:
        p = (path + " > " if path else "") + s["title"]
        for sp in s.get("specs", []):
            ok = sp.get("ok")
            for t in sp.get("tests", []):
                st = "PASS" if ok else ("SKIP" if t.get("status") == "skipped" else "FAIL")
                print(f"- {st}: {p} > {sp['title']}")
                if not ok:
                    for r in t.get("results", []):
                        err = plain((r.get("error") or {}).get("message", ""))
                        if err: print("  ```\n  " + err.strip().splitlines()[0][:300] + "\n  ```")
        walk(s.get("suites", []), p)
walk(d.get("suites", []))
EOF
    echo
  fi
  for scan in "zap:site and application (crawl)" "zap-api:JSON API (OpenAPI, active rules)"; do
    key=${scan%%:*}; label=${scan#*:}
    [ -f "$RUN/owasp/$key-report.json" ] || continue
    echo "## OWASP ZAP: $label"; echo
    grep -E '^(FAIL-NEW: |Total of)' "$RUN/owasp/$key.log" | sed 's/^/    /'
    echo
    python3 - "$RUN/owasp/$key-report.json" tests/owasp/zap.conf <<'EOF'
import json, sys
d = json.load(open(sys.argv[1]))
rated = {}
for line in open(sys.argv[2]):
    parts = line.split("\t")
    if len(parts) >= 2 and parts[0].strip().isdigit():
        rated[parts[0].strip()] = parts[1].strip()
print("| Risk | Alert | Rule | Hits | Where | Rated |")
print("|---|---|---|---|---|---|")
order = {"High": 0, "Medium": 1, "Low": 2, "Informational": 3}
alerts = [a for s in d.get("site", []) for a in s.get("alerts", [])]
for a in sorted(alerts, key=lambda a: (order.get(a["riskdesc"].split(" ")[0], 9), a["name"])):
    where = sorted(set("/" + i["uri"].split("//", 1)[-1].partition("/")[2].split("?")[0] for i in a["instances"]))
    where = ", ".join(where[:4]) + (" ..." if len(where) > 4 else "")
    print(f"| {a['riskdesc']} | {a['name']} | {a['pluginid']} | {a['count']} | {where} | {rated.get(a['pluginid'], 'WARN')} |")
EOF
    echo
    echo "Full report: owasp/$key-report.html (rules in tests/owasp/zap.conf decide FAIL, WARN or IGNORE)."
    echo
  done
} > "$REPORT"

echo
echo "=========== summary ==========="
sed -n '/^| Stage/,/^$/p' "$REPORT"
echo "Report: $REPORT"
exit $failed
