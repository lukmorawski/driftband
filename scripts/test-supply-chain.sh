#!/usr/bin/env sh
# Supply-chain stage: the container image (OS packages and Go modules), the
# repository (dependency files, misconfigured Dockerfile and compose, secrets
# in files) and the git history (leaked secrets). Needs only Docker. Output
# goes to the directory given as $1 (default: ./reports/supply-chain).
#
#   scripts/test-supply-chain.sh [outdir] [image]
#
# Exit status: 1 when the image or the repository has a CRITICAL or HIGH
# vulnerability with a fix available, or when gitleaks finds a secret.
set -eu
cd "$(dirname "$0")/.."
OUT=${1:-reports/supply-chain}
IMAGE=${2:-driftband:test}
mkdir -p "$OUT"
OUT=$(cd "$OUT" && pwd)
status=0

trivy() {
  docker run --rm -v /var/run/docker.sock:/var/run/docker.sock -v driftband-trivy-cache:/root/.cache \
    -v "$PWD:/repo:ro" -v "$OUT:/out" aquasec/trivy:latest "$@"
}

docker image inspect "$IMAGE" >/dev/null 2>&1 || { echo "==> building $IMAGE"; docker build -q -t "$IMAGE" . >/dev/null; }

echo "==> trivy image $IMAGE"
trivy image --quiet --ignorefile /repo/.trivyignore --scanners vuln,secret,misconfig --format json --output /out/trivy-image.json "$IMAGE" >/dev/null
trivy image --quiet --ignorefile /repo/.trivyignore --scanners vuln,secret,misconfig --format table "$IMAGE" > "$OUT/trivy-image.txt" 2>&1 || true

# .env is the local settings file (never committed, see .gitignore); what is
# committed is covered here and by gitleaks below.
echo "==> trivy repository (dependencies, Dockerfile, compose, secrets)"
trivy fs --quiet --ignorefile /repo/.trivyignore --scanners vuln,secret,misconfig --skip-dirs reports --skip-dirs tests/e2e/node_modules --skip-files .env \
  --format json --output /out/trivy-repo.json /repo >/dev/null
trivy fs --quiet --ignorefile /repo/.trivyignore --scanners vuln,secret,misconfig --skip-dirs reports --skip-dirs tests/e2e/node_modules --skip-files .env \
  --format table /repo > "$OUT/trivy-repo.txt" 2>&1 || true

python3 - "$OUT/trivy-image.json" "$OUT/trivy-repo.json" > "$OUT/trivy-summary.txt" <<'EOF' || status=1
import json, sys
blocking = 0
for path in sys.argv[1:]:
    d = json.load(open(path))
    vulns, secrets, misconf = [], [], []
    for r in d.get("Results") or []:
        vulns += r.get("Vulnerabilities") or []
        secrets += r.get("Secrets") or []
        misconf += [m for m in (r.get("Misconfigurations") or []) if m.get("Status") == "FAIL"]
    by = {}
    for v in vulns:
        by[v["Severity"]] = by.get(v["Severity"], 0) + 1
    fixable = [v for v in vulns if v["Severity"] in ("CRITICAL", "HIGH") and v.get("FixedVersion")]
    print(f"{path.split('/')[-1]}: {len(vulns)} vulnerabilities {by or ''}, {len(fixable)} critical/high with a fix, "
          f"{len(secrets)} secrets, {len(misconf)} misconfigurations")
    for v in fixable:
        print(f"  {v['VulnerabilityID']} {v['PkgName']} {v['InstalledVersion']} -> {v['FixedVersion']} ({v['Severity']})")
    for s in secrets:
        print(f"  secret: {s.get('RuleID')} {s.get('Title')} line {s.get('StartLine')}")
    for m in misconf:
        print(f"  misconfig: {m.get('ID')} [{m.get('Severity')}] {m.get('Title')}")
    blocking += len(fixable) + len(secrets)
sys.exit(1 if blocking else 0)
EOF
cat "$OUT/trivy-summary.txt"

echo "==> gitleaks (secrets in the git history and the work tree)"
if docker run --rm -v "$PWD:/repo:ro" -v "$OUT:/out" zricethezav/gitleaks:latest \
     git --redact --no-banner --config /repo/.gitleaks.toml --report-format json --report-path /out/gitleaks.json /repo > "$OUT/gitleaks.txt" 2>&1; then
  echo "ok: no leaks"
else
  status=1
  echo "leaks found (details in gitleaks.json, values redacted):"; tail -n 5 "$OUT/gitleaks.txt"
fi

exit $status
