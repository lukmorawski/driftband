# Testing

Driftband is tested on four layers. All of them run from Docker; nothing
else is installed on the machine. One command runs everything and writes a
report:

```bash
scripts/test-all.sh
```

| Layer | Script | What it checks |
|---|---|---|
| Backend | `scripts/test-backend.sh` | gofmt, go vet, the Go test suite with coverage (every API route through the security matrix, feature rules, the measurement pipeline), gosec static analysis, govulncheck against the Go vulnerability database |
| Supply chain | `scripts/test-supply-chain.sh` | Trivy on the container image and the repository (OS packages, Go modules, Dockerfile and compose misconfigurations, secrets in files), gitleaks on the git history |
| Frontend | `scripts/test-frontend.sh` | Playwright in Chromium against a throwaway instance: module tests of `web/js` in the real browser, end-to-end flows through the UI, browser-side security checks |
| OWASP | `scripts/test-owasp.sh` | OWASP ZAP against the throwaway instance, signed in: a crawl of the application (classic and client spider) with the passive rules, then the JSON API from `tests/owasp/openapi.yaml` with the active API rules; `--active` adds the active scan of the crawled pages as well |

The backend layer alone is `scripts/security-tests.sh`, the suite every
change must keep green (see [SECURITY-TESTING.md](SECURITY-TESTING.md) for
the security rules it enforces). CI runs that layer on every push; the full
suite is run on request before a release or after larger changes.

## Running

```bash
scripts/test-all.sh                  # all layers, no active scan (about 10 minutes)
scripts/test-all.sh --active         # with ZAP's active scan (adds 15-60 minutes)
scripts/test-all.sh --only frontend  # one layer: backend, supply, frontend, owasp
scripts/test-all.sh --skip owasp     # all but one layer
```

Every run writes `reports/<timestamp>/REPORT.md` (one line per layer, then
the details: uncovered functions, gosec and govulncheck output, Trivy
summary, every browser test with its result, ZAP's findings) and keeps the
raw output next to it: logs, `coverage.html`, Trivy and ZAP reports in
JSON, HTML and Markdown, and a trace, screenshot and page snapshot for each
failed browser test (open the trace with `npx playwright show-trace`).
`reports/latest` points at the newest run. The directory is not committed.

Results per layer:

- **PASS**: nothing to do.
- **WARN**: findings to review. ZAP warnings, gosec and govulncheck
  findings and Trivy vulnerabilities without a fix are reported, not
  failed; a person decides what to change, what to accept, and records
  accepted ones with the reason next to them (ZAP: `tests/owasp/zap.conf`;
  Trivy: `.trivyignore`; gitleaks: `.gitleaks.toml`; gosec: a `#nosec`
  comment on the line).
- **FAIL**: must be fixed or justified before a release: a failing test,
  a ZAP rule marked FAIL in `tests/owasp/zap.conf`, a CRITICAL or HIGH
  vulnerability with a fix available, a secret in the repository.

The first run pulls the tool images (Playwright, ZAP, Trivy, gitleaks;
about 4 GB) and installs the Playwright package into a Docker volume; later
runs reuse both.

### The throwaway instance

Browser and OWASP tests run against an instance built from the checkout
(`scripts/test-stack.sh up DIR`): the image with the same hardening as
`docker-compose.yml` (read-only, no capabilities, non-root), PostgreSQL in
memory, and no port published on the host. The tools join its Docker
network and use `http://sut:8080`. Security keys and passkeys need a secure
context and a host name of two labels, so the stack also answers to
`http://driftband.localhost:8080` (its `APP_URL`); the WebAuthn browser
tests use that address with Chromium's virtual authenticators. The stack is
seeded with a platform administrator and an organization for the scanner;
their credentials are written to `DIR/stack.env` (mode 600) and passed to
the tools. The stack is removed after the run (`scripts/test-stack.sh down`).

To test an image you built yourself, name it in `TEST_IMAGE` and set
`TEST_BUILD=no`. `E2E_EXTRA_SPECS` names a directory with additional
browser tests (for example those of your own deployment); they run with
the suite.

Hosts added during the tests are probed for real by fping inside the
container, so a chart with data is part of the test (`127.0.0.1`, 5-second
profile).

### Working on one layer

```bash
scripts/test-stack.sh up reports/dev
scripts/test-frontend.sh reports/dev/e2e --grep @security      # tags: @unit @e2e @security
scripts/test-frontend.sh reports/dev/e2e specs/auth.spec.js    # one file
scripts/test-owasp.sh reports/dev/owasp
scripts/test-stack.sh down
scripts/security-tests.sh -run TestSeries                      # one backend test
```

Browser tests live in `tests/e2e/specs`, helpers in `tests/e2e/helpers.js`.
`specs/instance.spec.js` changes settings of the whole instance (it closes
it to new organizations for a moment), so it runs in a project of its own
after all other specs have finished.
The Playwright version is pinned in `tests/e2e/package.json`; the matching
browser image is picked from it. To upgrade, change the version there and
run the frontend layer once (the lock file is updated in place).

## Coverage of the OWASP Top 10 (2021)

| Risk | Where it is tested |
|---|---|
| A01 Broken access control | `TestRoleEnforcement`, `TestTenantIsolation`, `TestAuditLogIsReadOnlyAndScoped`, `TestSuperadminFlagNotSelfAssignable`, `TestTeamSignInDetails`, `TestRegistrationCanBeClosed` and the admin tests (backend); "tenants and roles are enforced", "a member only reads" and the admin flows (browser); ZAP, signed in |
| A02 Cryptographic failures | `TestPasswordsStoredAsArgon2id`, `TestChannelSecretsNeverExposed`, `TestChannelsSealedWithSalt`, `TestTotpSecretSealed`, `TestSealedRecords` (AES-256-GCM at rest, per-record salt), `TestSessionCookieFlags`, `TestSessionTokens`; "the session cookie is HttpOnly, SameSite" and "a channel keeps its secret" (browser) |
| A03 Injection | `TestInjectionAndMalformedInput`, `TestHostAddressValidation` (fping arguments), `TestImportRejectsNonConfigFiles`, `TestMassAssignmentRejected`; "stored script payloads render as text", "every view loads without CSP violations" (browser); ZAP passive and active rules (XSS, SQL, command, path) |
| A04 Insecure design | `TestAvatarUpload`, `TestAvatarParsersOnGarbage` (file type, size and pixel limits, decompression bombs), `TestLoginRateLimited`, `TestPasswordConfirmationRateLimited`, `TestLoginDoesNotRevealAccounts`, `TestTurnstile` (no password is checked before the challenge is passed), limits and profile rules, alert evaluator tests (no false positives, flap suppression); "ten wrong passwords lock the account" (browser) |
| A05 Security misconfiguration | `TestSecurityHeaders`, `TestStaticFilesConfined`, `TestClientIPNotSpoofable`, `TestHealth`; "security headers", "the application cannot be framed", "cross-site requests cannot act on the session" (browser); Trivy misconfiguration rules for the Dockerfile and compose; the hardened container runs the browser tests; ZAP header rules |
| A06 Vulnerable and outdated components | govulncheck (Go modules in the binary's call graph), Trivy (image packages and modules), the pinned base images |
| A07 Identification and authentication failures | `TestTwoFactor`, `TestSecurityKeyAsSecondFactor`, `TestPasskeyEnrollmentRules`, `TestSessionTokens`, `TestPasswordChange`, `TestEmailChange`, `TestInvites`, `TestUserRemovalRules`, `TestAdminBlockUser`; the authentication and team flows, "security key" and "passkey" with virtual authenticators (browser) |
| A08 Software and data integrity failures | gitleaks and Trivy secret scanning; no third-party scripts in the application (browser); import validation; the release workflow attaches an SBOM and provenance |
| A09 Security logging and monitoring failures | `TestEveryChangeIsAudited` (every state change, with user and client IP), `TestAdminViewsAndGlobalAudit`; "retention, usage and the audit log" and the tenant view of admin actions (browser) |
| A10 Server-side request forgery | `TestWebhookSSRFBlocked`, `TestChannelValidation` (HTTPS, public addresses, re-checked on connect) |

## Every change extends the suite

A change is complete when the tests cover it, on every layer it touches:

1. **API route added or changed**: register it in `apiRoutes()` and add
   its `securityMatrix` entry; the generic tests then cover
   authentication, roles, tenant isolation and the audit trail. Feature
   rules get their own `Test...` next to the existing ones. Describe the
   route in `tests/owasp/openapi.yaml` so the API scan attacks it.
2. **Behaviour of the measurement pipeline, tree, profiles or housekeeping**:
   a functional test in `backend/features_test.go` (or the file of the
   feature).
3. **User interface**: a browser test for the flow in `tests/e2e/specs`
   (what a user does and what they must see), and a module test when
   `web/js` gains reusable logic.
4. **New trust boundary** (a new input, a new role, data shown to another
   tenant, a new outbound connection): a check in
   `tests/e2e/specs/security.spec.js` or the backend suite, and a look at
   the ZAP report of the next full run.
5. Run `scripts/security-tests.sh` before committing and
   `scripts/test-all.sh` before a release.
