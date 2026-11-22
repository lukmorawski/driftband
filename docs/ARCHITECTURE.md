# Architecture

Driftband is two containers: the application (one Go binary that also
serves the web interface) and PostgreSQL. There is no message queue, no
cache and no separate worker process; everything below runs inside the one
binary.

```
                 browser
                    |  HTTPS (your reverse proxy)
                    v
  +-------------------------------------------+
  |  driftband container                      |
  |                                           |
  |  HTTP server --- JSON API (/api/...)      |
  |       |      \-- web interface (static)   |
  |       |                                   |
  |  prober manager --> fping (one process    |      ICMP echo
  |       |             per host and cycle) --------------------> your hosts
  |  rollup worker                            |
  |  alert evaluator --> notification senders -----> Telegram, Slack,
  |  housekeeper                              |      Teams, SMTP
  +-----------------------|-------------------+
                          v
                     PostgreSQL
```

## Repository layout

| Path | Contents |
|---|---|
| `backend/` | the Go application: API, background workers, schema, tests |
| `web/` | the web interface: plain ES modules, no framework, no build step in development |
| `scripts/` | test runners, the asset stamping step of the image build, the PostgreSQL upgrade |
| `tests/e2e/` | browser tests (Playwright) |
| `tests/owasp/` | OWASP ZAP rules and the OpenAPI description used by the API scan |
| `licenses/` | license texts of the bundled web components |
| `docs/` | this documentation and the Docker Hub overview |
| `Dockerfile`, `docker-compose.yml` | the image build and a ready stack |

## The path of a measurement

1. **Prober manager** (`prober.go`). Keeps one goroutine per host and
   compares them with the database every 20 seconds and right after a host
   or profile is edited. Each goroutine ticks at the interval of the host's
   probe profile and runs one cycle: `fping -C <pings> -b <size> -p 200 -q
   <address>`, which sends the pings 200 ms apart and prints every
   round-trip time. fping runs as a separate process without privileges
   (unprivileged ICMP sockets). The address is validated before it is
   stored and again here, and can never begin with `-`.
2. **Samples** (`samples` table). One row per cycle: the time, pings sent
   and received, and the array of round-trip times. Nothing is averaged at
   this point, which is what makes percentile bands possible. A cycle
   takes about 370 bytes; one host probed every minute is roughly 190 MB a
   year.
3. **Rollup worker** (`rollup.go`). Every 5 minutes it summarises the
   completed hours of each host into two tiers, 5-minute and 1-hour
   buckets (`sample_rollups`). A bucket stores nine percentiles of all
   round-trip times pooled across the bucket (not an average of cycle
   percentiles) and the counters needed to compute loss and median
   statistics exactly. A watermark per host (`rollup_state`) records how
   far the rollups are complete.
4. **Series API** (`series.go`, `GET /api/series`). The chart asks for a
   time window and the number of columns it can draw. Short windows are
   answered from raw cycles, pooled into buckets when there are more
   cycles than columns; long windows come from the rollup tier that fits,
   with a raw tail for the latest period the rollups do not cover yet.
   Statistics for the legend are computed over every cycle of the window,
   not over the downsampled points.
5. **Chart** (`web/js/chart.js`). Draws the bands, the median line coloured
   by loss and the loss strip with [uPlot](https://github.com/leeoniya/uPlot)
   on a canvas; zoom, synchronised cursors and live refresh are handled in
   the browser.
6. **Housekeeper** (`housekeeper.go`). Once at start and then daily it
   deletes samples and rollups older than each organization's retention
   (1, 2 or 3 years) and clears expired sessions and invitations.

## Alerts and notifications

The **alert evaluator** (`alerts.go`) runs every 30 seconds. For each rule
it measures every host in the rule's scope (one host, a folder with its
subtree, or the whole organization) over a short lookback of a few probe
cycles, on packet loss or median latency. A rule fires only after the
threshold has been exceeded for its hold time and resolves only after the
value has stayed under a lower recovery threshold for the recovery time
(hysteresis). Repeated changes within a window mark the pair as flapping:
one message is sent and further ones are held back until the state is
stable. A period without samples neither fires nor resolves.

**Notification channels** (`notify.go`) are Telegram, Slack, Microsoft
Teams (Workflows webhook) and email over SMTP with a password or OAuth 2.0
client credentials. Webhook and token URLs must be HTTPS on public
addresses; the address is checked again when the connection is made, so a
DNS answer that changes cannot redirect a request to an internal service.
Every delivery is recorded in the delivery log.

## Accounts, tenants and access

- **Organizations** are isolated tenants. Every table that holds tenant
  data carries the organization id and every query filters on it; another
  organization addressing your objects gets "not found".
- **Roles**: owner, admin, member. Members work with hosts and probe
  profiles and read everything else; owners and admins also manage the
  team and invitations, imports, retention, alert rules and notification
  channels. A **platform
  administrator** (a flag set only in the database, never through the API)
  sees all organizations, can block or delete them and set host limits.
- **Passwords** are hashed with Argon2id (64 MB, unique salt). Sessions
  are random 256-bit tokens in an HttpOnly, SameSite cookie, valid for 30
  days and revocable on the server.
- **Two-factor sign-in** (`totp.go`, `webauthn.go`): TOTP codes with
  replay protection, hardware security keys and passkeys (WebAuthn).
  Enrolled factors are a second step after the password.
- **Rate limiting** (`ratelimit.go`): failed passwords and codes are
  counted per account and per client address in a 15-minute window, in
  memory.
- **Audit log** (`audit.go`): every state change, failed sign-in and
  refused permission check is written with the user and client address.
  Organizations read their own log; events without an organization are
  visible to platform administrators only.

## Secrets at rest

`secrets.go` seals what must not be readable in the database: whole
notification channels (addresses, accounts, tokens, passwords), TOTP
secrets and WebAuthn credential records. Each record gets a random salt;
its key is derived from the master key (`SECRET_KEY`) and that salt with
HKDF-SHA256, and the data is encrypted with AES-256-GCM. What the record is
and whom it belongs to is authenticated with it, so a value copied to
another row does not open. An account whose stored second factor can no
longer be opened cannot sign in with the password alone.

## HTTP server

`main.go` and `http.go` register every API route in one table
(`apiRoutes()`); the test suite refuses a route that has no entry in the
security matrix. All responses carry a Content Security Policy without
inline scripts or styles, `nosniff`, frame denial and the cross-origin
isolation headers; API responses are never cached. The client address is
taken from `X-Forwarded-For` only when the request comes from a trusted
proxy. JSON bodies are limited to 1 MB and unknown fields are rejected.

The web interface is served from `WEB_DIR` as static files with a fallback
to `index.html` for client-side routes. The image build bundles and
minifies the scripts and stamps every asset URL with a content hash, so
assets are cached for a year and a new build is picked up at once.
Optionally a static website can be served under `/main` (`LANDING_DIR`).

## Web interface

`web/main.js` is the entry point; `web/js/api.js` wraps the API,
`web/js/ui.js` holds the small DOM helper everything is built with, and
each screen is one module in `web/js/views/` (dashboard, alerts,
notifications, settings, usage, administration, sign-in, help). The only
third-party code in the browser is uPlot and a QR code generator, both
vendored in `web/vendor/`; the interface makes no requests to other
origins.

## Database

PostgreSQL 18. The schema (`backend/schema.sql`) is embedded in the binary
and applied at every start; all statements are idempotent, so starting a
newer version upgrades the schema in place.

| Tables | Purpose |
|---|---|
| `organizations`, `users`, `sessions`, `invites` | tenants, accounts, sign-in state |
| `webauthn_credentials`, `webauthn_challenges`, `user_avatars` | second factors and profile pictures |
| `probe_profiles`, `nodes` | probe settings and the tree of folders and hosts |
| `samples`, `sample_rollups`, `rollup_state` | measurements and their summaries |
| `alert_rules`, `alert_state`, `notify_channels`, `notify_log` | alerting |
| `audit_log`, `db_size_history`, `app_settings` | audit trail, storage trend, instance settings |

The two measurement tables have their own autovacuum settings so that the
space of a deleted host is reused within about a minute.

## Container image

The image is Alpine with the binary, the web interface, fping and the
license texts. It runs as a fixed non-root user (uid 10001), needs no
Linux capabilities, works with a read-only root filesystem and has a
built-in health check. The build is multi-stage: the Go binary is
cross-compiled for the target platform, the web assets are bundled with
esbuild, and only the results are copied into the runtime stage.
