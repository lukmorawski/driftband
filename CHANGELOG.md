# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.1] - 2026-11-22

### Added
- Cloudflare Turnstile on the sign-in, organization and invitation forms,
  off by default (`TURNSTILE_ENABLE`, `TURNSTILE_SITE_KEY`,
  `TURNSTILE_SECRET_KEY`). The server verifies the answer before it checks
  anything else; a two-factor sign-in is challenged once.
- Admin, Settings: a platform administrator can turn off creating
  organizations. The sign-in page then offers only signing in, and new
  people join through invitations.
- `GET /api/health` for load balancers and monitoring: 200 when the
  application and its database are available, 503 otherwise.

### Changed
- The container health check uses `/api/health` instead of `/robots.txt`,
  so a container whose database is gone is reported as unhealthy.
- Documentation: reverse proxy examples for nginx, Apache, HAProxy and
  Traefik (the application has no TLS of its own, by design), accounts and
  invitations, Turnstile, monitoring, and a notice on responsible use.

## [0.1.0] - 2026-11-22

First public release.

### Measurements
- Smoke graphs: the distribution of round-trip times as percentile bands,
  a median line coloured by packet loss, a loss strip, legend statistics,
  drag to zoom, synchronised cursors, live mode and a classic view.
- Probing with fping over IPv4 and IPv6, by address or host name. Probe
  profiles set the interval, the pings per cycle and the packet size; new
  hosts take the default profile.
- Long time ranges are served from 5-minute and hourly rollups; each
  organization keeps 1, 2 or 3 years of history.
- Host tree with folders and hosts, arranged with drag and drop.
- SmokePing import: paste a `Targets` configuration to recreate its folders
  and hosts. Plain text only, validated, all or nothing.
- Active Alerts page, usage view with stored measurements per host, data
  size, growth and a storage forecast.

### Alerts
- Rules on packet loss or median latency for a host, a folder or the whole
  organization, with hold times, a lower recovery threshold, reminders and
  flap suppression.
- Notifications through Telegram, Slack, Microsoft Teams and email (SMTP
  with STARTTLS or TLS, password or OAuth 2.0 client credentials, with a
  Microsoft 365 preset), a test button per channel and a delivery log.

### Accounts and security
- Organizations with owner, admin and member roles, single-use invite
  links, team management with last sign-in and second factors shown to
  owners and admins, profile pictures.
- Argon2id password hashing, rate-limited sign-in and password
  confirmations, sessions in HttpOnly SameSite cookies.
- Two-factor sign-in with hardware security keys and passkeys (WebAuthn)
  or TOTP codes with replay protection.
- Notification channels, TOTP secrets and security-key records are
  encrypted at rest with a per-record salt (AES-256-GCM, keys derived with
  HKDF-SHA256) and bound to their owner.
- Strict Content Security Policy without inline scripts or styles,
  cross-origin isolation headers, SSRF-checked webhooks.
- Audit log of every action, including failed sign-ins and refused
  operations.
- Platform administration: organizations and users, blocking, password
  and two-factor resets, host limits, organization removal, database usage
  and a global audit log.
- Optional limits for a public demo instance (`TEST_INSTANCE`).

### Operations
- Container image for `linux/amd64` and `linux/arm64`: non-root user, no
  Linux capabilities, read-only root filesystem, health check, SBOM and
  provenance attestations.
- PostgreSQL 18; the schema is applied at start.
  `scripts/upgrade-postgres.sh` moves the data to a new PostgreSQL major
  version.
- Test suite on four layers: backend with the security matrix over every
  API route, supply chain scanning, browser tests and OWASP ZAP.

[Unreleased]: https://github.com/lukmorawski/driftband/compare/v0.1.1...HEAD
[0.1.1]: https://github.com/lukmorawski/driftband/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/lukmorawski/driftband/releases/tag/v0.1.0
