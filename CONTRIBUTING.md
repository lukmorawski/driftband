# Contributing to Driftband

Thanks for your interest. A few ground rules.

## License & sign-off (DCO)

Driftband is licensed under **AGPL-3.0-or-later**. To keep the project's options
open (including the possibility of offering commercial/dual licenses in the
future), every contribution must be made under the
**Developer Certificate of Origin** ([DCO 1.1](https://developercertificate.org/)).

Sign off every commit:

```bash
git commit -s -m "your message"
```

This adds a `Signed-off-by: Your Name <you@example.com>` line, certifying you
have the right to submit the work under the project's license.

## Development

- Keep changes focused and match the surrounding code style.
- The backend (`backend/`) is Go over PostgreSQL (`pgx`), with the schema in
  `backend/schema.sql` applied at startup. The frontend (`web/`) is a vanilla
  ES-module SPA with [uPlot](https://github.com/leeoniya/uPlot) - no build step
  for development. The image build bundles `main.js` with its modules,
  minifies the files and stamps every asset URL with a content hash
  (`scripts/web-version.sh`), so assets are cached for a year and a new
  build still shows up at once. `web/` is baked into the image, so changes
  show up after `docker compose up -d --build`.
- Run the stack locally before submitting:

  ```bash
  docker compose up -d --build
  # UI on http://localhost:8080 - create an organization to begin
  ```

- For frontend-only work you can bind-mount `web/` into the container (add a
  `docker-compose.override.yml`, which is gitignored) to skip rebuilds.
- Every change must pass the security test suite, and every new feature must
  extend it (new routes need a `securityMatrix` entry, state changes must be
  audited). See [SECURITY-TESTING.md](SECURITY-TESTING.md):

  ```bash
  scripts/security-tests.sh
  ```

- A new feature is complete when it is covered on every layer it touches:
  backend tests, a browser test for its UI flow, and a security check for
  any new trust boundary. The whole suite (backend, supply chain, browser
  tests, OWASP ZAP) is `scripts/test-all.sh`; see [TESTING.md](TESTING.md).

- Open an issue first for larger changes so we can agree on direction.

How the parts fit together is described in
[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Releases

Releases follow [Semantic Versioning](https://semver.org). A release is a
commit that sets `VERSION` and moves the changelog entries under the new
version, tagged `vX.Y.Z`. The tag starts the Release workflow
(`.github/workflows/release.yml`): it runs the tests, builds the image for
`linux/amd64` and `linux/arm64` with SBOM and provenance attestations,
pushes it to Docker Hub as `X.Y.Z`, `X.Y` and `latest`, and updates the
Docker Hub overview from `docs/dockerhub/`.
