#!/usr/bin/env sh
# Updates the Docker Hub repository's short description and overview from
# docs/dockerhub/. Run by the Release workflow; credentials come from the
# environment and are never printed or stored:
#
#   DOCKERHUB_USERNAME  account name
#   DOCKERHUB_TOKEN     Personal Access Token allowed to change the
#                       repository's settings
#
#   scripts/dockerhub-description.sh
set -eu
cd "$(dirname "$0")/.."
REPO=${REPO:-lukmorawski/driftband}
: "${DOCKERHUB_USERNAME:?set DOCKERHUB_USERNAME}" "${DOCKERHUB_TOKEN:?set DOCKERHUB_TOKEN}"
export REPO DOCKERHUB_USERNAME DOCKERHUB_TOKEN

python3 - <<'PY'
import json, os, sys, urllib.request, urllib.error

def call(method, url, body, token=None):
    req = urllib.request.Request(url, data=json.dumps(body).encode(), method=method,
                                 headers={"Content-Type": "application/json"})
    if token:
        req.add_header("Authorization", "Bearer " + token)
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            return r.status, json.loads(r.read() or b"{}")
    except urllib.error.HTTPError as e:
        try:
            return e.code, json.loads(e.read() or b"{}")
        except ValueError:
            return e.code, {}

user, secret, repo = os.environ["DOCKERHUB_USERNAME"], os.environ["DOCKERHUB_TOKEN"], os.environ["REPO"]
status, out = call("POST", "https://hub.docker.com/v2/users/login", {"username": user, "password": secret})
jwt = out.get("token")
if not jwt:
    sys.exit(f"Docker Hub login failed (HTTP {status})")

short = open("docs/dockerhub/short-description.txt").read().strip()
full = open("docs/dockerhub/README.md").read()
if len(short) > 100:
    sys.exit("docs/dockerhub/short-description.txt is longer than 100 characters")
status, out = call("PATCH", f"https://hub.docker.com/v2/repositories/{repo}/",
                   {"description": short, "full_description": full}, jwt)
if status != 200:
    sys.exit(f"update failed (HTTP {status}): {out.get('detail') or out.get('message') or ''}")
print(f"Updated {repo}: short description and overview.")
PY
