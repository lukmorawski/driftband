#!/usr/bin/env sh
# Backend stage of the test suite: formatting, go vet, the whole Go test
# suite with coverage (security tests included, see SECURITY-TESTING.md),
# gosec static analysis and govulncheck against the Go vulnerability
# database. Needs only Docker. Output goes to the directory given as $1
# (default: ./reports/backend).
#
#   scripts/test-backend.sh [outdir]
#
# Exit status: 0 when formatting, vet and the tests pass. gosec and
# govulncheck findings are written to the report but do not fail the stage;
# they are reviewed by a person.
set -eu
cd "$(dirname "$0")/.."
OUT=${1:-reports/backend}
mkdir -p "$OUT"
OUT=$(cd "$OUT" && pwd)
GO_IMAGE=golang:1.27-alpine
status=0

gorun() {
  docker run --rm -v "$PWD/backend:/src" -w /src -v driftband-gocache:/go \
    -e GOFLAGS=-buildvcs=false -e CGO_ENABLED=0 -e GOMAXPROCS=2 "$@"
}

echo "==> gofmt"
if gorun "$GO_IMAGE" gofmt -l . > "$OUT/gofmt.txt" 2>&1 && [ ! -s "$OUT/gofmt.txt" ]; then
  echo "ok"
else
  echo "files need gofmt:"; cat "$OUT/gofmt.txt"; status=1
fi

echo "==> go vet"
if gorun "$GO_IMAGE" go vet ./... > "$OUT/vet.txt" 2>&1; then echo "ok"; else cat "$OUT/vet.txt"; status=1; fi

echo "==> go test (security suite, with coverage)"
# -v so the report can count tests; the coverage profile lands in backend/
# (mounted as /src) and is moved out afterwards.
if scripts/security-tests.sh -v -covermode=atomic -coverprofile=/src/.cover.out > "$OUT/test.txt" 2>&1; then
  echo "ok: $(grep -c '^--- PASS' "$OUT/test.txt") passed, $(grep -c '^--- SKIP' "$OUT/test.txt") skipped"
else
  status=1
  echo "FAILED: $(grep -c '^--- FAIL' "$OUT/test.txt") failed"
  grep -E '^(--- FAIL|FAIL|panic:)' "$OUT/test.txt" | head -20
fi
if [ -f backend/.cover.out ]; then
  mv backend/.cover.out "$OUT/cover.out"
  gorun -v "$OUT:/out" "$GO_IMAGE" go tool cover -func=/out/cover.out > "$OUT/coverage.txt" 2>&1 || true
  gorun -v "$OUT:/out" "$GO_IMAGE" go tool cover -html=/out/cover.out -o /out/coverage.html >/dev/null 2>&1 || true
  echo "coverage: $(tail -n 1 "$OUT/coverage.txt" | awk '{print $NF}')"
fi

echo "==> gosec (static analysis)"
# gosec is compiled for the run, and two of its dependencies need about
# 2 GB each to compile: one package at a time (-p=1) and an eager garbage
# collector (GOGC) keep that within a small VM's memory.
gorun -e GOTOOLCHAIN=auto -e GOMAXPROCS=2 -e GOGC=50 -e GOFLAGS="-buildvcs=false -p=1" "$GO_IMAGE" sh -c \
  'go run github.com/securego/gosec/v2/cmd/gosec@latest -fmt json -out /src/.gosec.json ./... ; true' > "$OUT/gosec.log" 2>&1 || true
if [ -f backend/.gosec.json ]; then
  mv backend/.gosec.json "$OUT/gosec.json"
  python3 - "$OUT/gosec.json" <<'EOF' | tee "$OUT/gosec.txt"
import json, sys
d = json.load(open(sys.argv[1]))
issues = d.get("Issues") or []
print(f"{len(issues)} findings")
for i in issues:
    print(f"[{i['severity']}/{i['confidence']}] {i['rule_id']} {i['file'].split('/src/')[-1]}:{i['line']}: {i['details']}")
EOF
else
  echo "gosec did not produce a report"; tail -5 "$OUT/gosec.log"
fi

echo "==> govulncheck (Go vulnerability database)"
if gorun -e GOTOOLCHAIN=auto "$GO_IMAGE" go run golang.org/x/vuln/cmd/govulncheck@latest ./... > "$OUT/govulncheck.txt" 2>&1; then
  echo "ok: no known vulnerabilities in the binary's call graph"
else
  echo "findings (see govulncheck.txt):"; grep -E '^Vulnerability|^ +[A-Z]' "$OUT/govulncheck.txt" | head -20
fi

exit $status
