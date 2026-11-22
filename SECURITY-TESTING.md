# Security testing procedure

Driftband has an automated security test suite
(`backend/security_test.go`, harness in `backend/testenv_test.go`). It runs
against a real PostgreSQL and the real HTTP router, so it exercises exactly
what is deployed. **Every change must keep it green, and every new feature
must extend it.** It is the backend layer of the full suite described in
[TESTING.md](TESTING.md) (browser tests, OWASP ZAP, image and dependency
scanning), which maps every OWASP Top 10 risk to the tests that cover it.

## Running

Only Docker is needed:

```bash
scripts/security-tests.sh                      # whole suite
scripts/security-tests.sh -run TestTwoFactor   # one test
scripts/security-tests.sh -v                   # with request logs
```

The script starts a throwaway Postgres, runs `go test ./...` in a Go
container and removes everything afterwards. CI runs the same suite
(`security-tests` job in `.github/workflows/ci.yml`); a red run blocks the
merge.

Without `TEST_DATABASE_URL` the database tests are skipped, but
`TestEveryRouteIsCovered` still runs, so `go test ./...` alone catches an
uncovered route.

## What is covered

Generic checks, run for **every API route** listed in `securityMatrix`:

| Test | Guarantees |
|---|---|
| `TestEveryRouteIsCovered` | every route in `apiRoutes()` has a matrix entry; GET never changes state; every state change declares an audit action |
| `TestUnauthenticatedRequestsRejected` | no session, forged token and expired session all get 401 |
| `TestRoleEnforcement` | admin-only routes refuse members (403, audited as `denied.*`) and work for admins and owners; platform routes (`/api/admin/*`) refuse every tenant role and work only for superadmins; member routes work for members |
| `TestTenantIsolation` | another organization addressing your objects gets 404 and changes nothing; list endpoints never show foreign data |
| `TestEveryChangeIsAudited` | each successful change writes its audit action with user and client IP |

Specific checks:

- **Passwords**: Argon2id with unique salts, no plaintext; registration
  validation; change needs the current password and a matching
  confirmation, signs out other sessions; password confirmations are rate
  limited.
- **Login**: identical errors and similar timing for unknown email vs wrong
  password; per-account and per-IP lockout (429) that rotating
  `X-Forwarded-For` cannot dodge; failures and lockouts audited.
- **Client IP**: `X-Forwarded-For` is honoured only from trusted proxies and
  read from the right (rightmost address that is not a trusted proxy), so
  entries supplied by the client cannot spoof the audit-log IP or the rate
  limit key.
- **Sessions**: HttpOnly + SameSite=Lax cookie, Secure over HTTPS (via a
  trusted proxy only), fresh 256-bit token per login, bounded lifetime,
  logout revokes server-side.
- **2FA**: password alone is not enough, wrong codes rejected and audited,
  codes cannot be replayed, secret cannot be swapped while enabled, disable
  needs the password.
- **TOTP secret at rest**: sealed and bound to the account; a value copied
  from another account, changed or unreadable accepts no code and does not
  fall back to the password alone; secrets of earlier versions keep
  working and are sealed at startup.
- **Security keys and passkeys**: enrolling and removing need the
  password; a passkey must verify the user; the password alone no longer
  signs in; an answer is refused when it is replayed, was collected on
  another origin, belongs to another account's challenge, comes from an
  unknown key or carries a signature counter that went backwards (copied
  key); every refusal is audited and counts toward the sign-in limit.
  Challenges are single use and expire. Credential records are sealed in
  the database, and an account whose records no longer open cannot sign
  in with the password alone; an administrator's two-factor reset removes them. The
  tests answer the challenges with a software authenticator
  (`backend/softkey_test.go`), so the real verification runs.
- **Profile pictures**: only JPEG, PNG, GIF and WebP by signature, with a
  matching declared type; at most 5 MB and 4096 x 4096 pixels, checked
  from the header before decoding (decompression bombs); uploads are rate
  limited; the stored picture is the server's own 256 x 256 re-encoding
  (appended data and metadata do not survive); only the user's own
  organization can fetch it; the header parsers are run against garbage.
- **Invites**: tokens hidden from members, single use, expiry, revocation, no
  escalation to owner.
- **Team**: removal rules (owner protected, admins cannot remove admins,
  removed users lose their sessions).
- **Input**: unknown JSON fields rejected (mass assignment), cross-tenant
  references refused, SQL/HTML payloads stored verbatim and served as JSON,
  malformed ids/JSON and NUL characters rejected with 400, 1 MB body limit,
  server-side clamps.
- **HTTP**: CSP without inline/eval scripts and, for the application,
  without inline styles (only an optional static website under `/main`,
  `LANDING_DIR`, allows them), `nosniff`, `X-Frame-Options`,
  `Referrer-Policy`, the cross-origin isolation headers (COOP, COEP, CORP), `no-store` on the API; no path
  traversal from the static handler; unknown API paths and non-GET SPA
  requests are not answered with 200.
- **Notifications**: a channel's settings and secrets (addresses,
  accounts, recipients, bot tokens, webhook URLs, SMTP passwords, OAuth
  client secrets) are sealed with AES-256-GCM under a key derived from the
  master key and a per-record salt, and bound to the organization: nothing
  but the name and kind is readable in the database, identical channels
  are stored differently, and a record copied to another organization or
  modified does not open. Rows of earlier versions are re-sealed at
  startup. Secrets are never returned by the API and kept out of delivery
  errors; webhooks and OAuth
  token URLs must be HTTPS on public addresses, re-checked when connecting
  (no SSRF to internal services or cloud metadata). SMTP hosts may be
  private on purpose (internal relays). Only owners and admins configure
  channels and rules; members can read them. The evaluator is tested for
  no false positives (blips, gaps without data), hysteresis, reminders and
  flap suppression, plus an end-to-end run from samples to delivery.
- **Import and hosts**: SmokePing import accepts only plain UTF-8 text
  (binary signatures such as PDF/ZIP/ELF, NUL and control bytes, U+FFFD,
  shebang scripts, PHP/HTML script tags are refused), at most 2 MB, 20 000
  lines and 1000 hosts per import, all-or-nothing. Every host address, in
  the import and in the API, must be an IP or host name and can never start
  with "-" (it is passed to fping as an argument); the prober re-checks.
- **Host deletion**: deleting a host removes all its data (samples,
  rollups, alert state); probe, alert and rollup work already running for
  it is dropped without leaving rows or errors behind.
- **Limits**: probe profiles need pings <= interval seconds and packets of
  12-1472 B; with TEST_INSTANCE=yes, 10 hosts per organization by default,
  interval >= 60 s and packets <= 56 B, enforced on create, import and in
  the prober, unless a platform admin exempts the organization.
- **Team sign-in details**: the last sign-in and the second factors of
  teammates are shown to owners and admins only; members see their own.
- **Team roles**: owners and admins switch others between admin and member;
  the owner's role and your own cannot be changed; changes apply at once.
- **Audit log**: read-only through the API and scoped to the organization;
  system events are visible only in the global log.
- **Organization removal**: only a platform administrator, confirmed with
  their password (rate limited, refusals audited) and the organization's
  exact name; never their own organization or one that holds a platform
  administrator. Nothing of the organization is left in any table, its
  users cannot sign in and their sessions are dead, other organizations
  are untouched, and the deletion is recorded in the system log with the
  administrator and client IP.
- **Paged lists**: page size clamped to 1-200, offsets bounded; a page
  never shows another organization's entries.
- **Instance settings**: only a platform administrator turns creating
  organizations off or on, and the change is in the system log. While it
  is off the server refuses to create organizations (nothing is left
  behind, the attempt is audited) and the sign-in page is told to hide the
  form; existing accounts sign in and invitations still work.
- **Turnstile** (with `TURNSTILE_ENABLE`): the sign-in, organization and
  invitation requests need a verified answer; without one nothing else is
  checked, the password included, and no failed attempt is counted. A
  refused answer is audited, an unreachable verification service refuses
  the request, an answer is accepted once. The pass for the second step
  of a two-factor sign-in is issued only after the right password, works
  for that account only and expires. The policy then allows Cloudflare's
  challenge origin for scripts and frames and nothing more; the secret key
  is never sent to the browser. The tests use a stand-in for Cloudflare's
  verification service.
- **Health endpoint**: answers without a session with nothing but the
  state of the application and its database, is never cached, and turns
  503 without leaking the database error.
- **Platform admin**: the superadmin flag cannot be set through any API;
  blocking a user or organization ends sessions, refuses sign-in (without
  revealing it to password guessers) and stops probing; temporary passwords
  are random, single-display and never logged; owners, yourself and other
  superadmins are protected; admin actions appear in the tenant's own log.

## Procedure for every change

1. **New or changed API route**: register it in `apiRoutes()`
   (`backend/main.go`) **and** add a `securityMatrix` entry
   (`backend/security_test.go`) with:
   - `minRole`: `public`, `member`, `admin` or `superadmin` (platform
     routes live under `/api/admin/` and are registered with `super: true`);
   - `call`: how to make a successful request against a test org;
   - `audit`: the audit action it records (required for anything that is
     not a GET);
   - `idor: true` if the path addresses an organization's object.

   `TestEveryRouteIsCovered` fails until this is done.
2. **Every state change is audited**: call `a.audit(...)` on success and
   `a.deny(...)` for refused permission checks. Sensitive actions that
   take a password use `a.checkPassword(...)` (rate limited and audited).
3. **Feature-specific rules** (limits, validation, special permissions,
   anything secret-bearing) get their own `Test...` function next to the
   existing ones.
4. Run `scripts/security-tests.sh`; it must pass before the change is
   committed or deployed.
5. In the pull request, tick the security checklist from the template.

## Deployment settings that matter

- `TRUSTED_PROXIES` (comma-separated CIDRs or addresses): peers whose
  `X-Forwarded-For` / `X-Forwarded-Proto` are believed. The default is
  loopback and private ranges (reverse proxy or tunnel on the same host or
  LAN). If the app is reachable directly from the internet through such an
  address range, narrow it to the proxy's address. Each trusted proxy must
  append the address it received the request from (nginx
  `$proxy_add_x_forwarded_for`, HAProxy `option forwardfor`); behind a CDN
  such as Cloudflare, add the CDN's published ranges as well.
- Serve over HTTPS through the proxy so the session cookie gets `Secure`.
