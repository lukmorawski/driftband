# Driftband

**Self-hosted smoke graphs for ICMP latency and packet loss. SmokePing, reimagined.**

Driftband pings your hosts with fping and draws the whole distribution of
round-trip times as percentile bands, with a median line coloured by packet
loss. Everything is configured in the browser: a host tree with drag and drop,
probe profiles, organizations and roles, single sign-on (Google, Microsoft
Entra ID), two-factor sign-in, notifications (Telegram, Slack, Microsoft
Teams, email, Zabbix) with flap detection, an audit log of every action, and
a one-paste import of your SmokePing Targets.

![Driftband smoke graphs](https://driftband.app/assets/img/shot-portale-dark.webp)

- Website: https://driftband.app
- What's new in each release: https://driftband.app/whats-new/
- Source and documentation: https://github.com/lukmorawski/driftband
- Try it without installing: https://test.driftband.app (10 hosts per organization)
- License: [AGPL-3.0-or-later](https://www.gnu.org/licenses/agpl-3.0.html)

## Quick start

Save as `docker-compose.yml`, create a `.env` file with the database password
and the key that encrypts notification secrets, then start it and open port
8080:

```bash
printf 'DB_PASSWORD=%s\nSECRET_KEY=%s\n' "$(openssl rand -hex 24)" "$(openssl rand -hex 32)" > .env
chmod 600 .env
docker compose up -d
```

```yaml
services:
  db:
    image: postgres:18-alpine
    restart: unless-stopped
    environment:
      POSTGRES_USER: driftband
      POSTGRES_PASSWORD: ${DB_PASSWORD:?set DB_PASSWORD in .env}
      POSTGRES_DB: driftband
    volumes:
      - pgdata:/var/lib/postgresql
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U driftband"]
      interval: 5s
      retries: 10

  driftband:
    image: lukmorawski/driftband:0.2.0
    restart: unless-stopped
    depends_on:
      db:
        condition: service_healthy
    environment:
      DATABASE_URL: postgres://driftband:${DB_PASSWORD:?set DB_PASSWORD in .env}@db:5432/driftband?sslmode=disable
      SECRET_KEY: ${SECRET_KEY:?set SECRET_KEY in .env}
      APP_URL: ${APP_URL:-}
      TRUSTED_PROXIES: ${TRUSTED_PROXIES:-}
      TURNSTILE_ENABLE: ${TURNSTILE_ENABLE:-no}
      TURNSTILE_SITE_KEY: ${TURNSTILE_SITE_KEY:-}
      TURNSTILE_SECRET_KEY: ${TURNSTILE_SECRET_KEY:-}
      SSO_GOOGLE_CLIENT_ID: ${SSO_GOOGLE_CLIENT_ID:-}
      SSO_GOOGLE_CLIENT_SECRET: ${SSO_GOOGLE_CLIENT_SECRET:-}
      SSO_GOOGLE_DOMAIN: ${SSO_GOOGLE_DOMAIN:-}
      SSO_ENTRA_TENANT_ID: ${SSO_ENTRA_TENANT_ID:-}
      SSO_ENTRA_CLIENT_ID: ${SSO_ENTRA_CLIENT_ID:-}
      SSO_ENTRA_CLIENT_SECRET: ${SSO_ENTRA_CLIENT_SECRET:-}
      SSO_ENTRA_AUTHORITY: ${SSO_ENTRA_AUTHORITY:-}
      NOTIFY_PRIVATE_TARGETS: ${NOTIFY_PRIVATE_TARGETS:-no}
    ports:
      - "8080:8080"
    read_only: true
    cap_drop: [ALL]
    security_opt: ["no-new-privileges:true"]
    sysctls:
      net.ipv4.ping_group_range: "0 2147483647"

volumes:
  pgdata:
```

The first person to register creates an organization and becomes its owner.

## Tags

| Tag | Meaning |
|---|---|
| `X.Y.Z` (e.g. `0.1.0`) | An exact release. Pin this in production. |
| `X.Y` (e.g. `0.1`) | The newest patch release of that minor version. |
| `X` (from 1.0 on) | The newest release of that major version. |
| `latest` | The newest release. Convenient for trying it out, not for production. |

Releases follow [Semantic Versioning](https://semver.org). Platforms: `linux/amd64`, `linux/arm64`.

## Configuration

| Variable | Default | Purpose |
|---|---|---|
| `DATABASE_URL` | (required) | PostgreSQL connection string (PostgreSQL 18 recommended) |
| `LISTEN` | `:8080` | HTTP listen address |
| `SECRET_KEY` | generated, stored in the database | 32-byte key (hex or base64) that encrypts notification channels and two-factor secrets; set it (as above) to keep the key out of the database, and keep it: without it channels and enrolled second factors cannot be read |
| `APP_URL` | (none) | Public URL of the instance: linked from notifications, and the address security keys and passkeys are bound to |
| `TRUSTED_PROXIES` | loopback and private ranges | Reverse proxies (CIDRs or addresses) whose `X-Forwarded-For` / `-Proto` headers are trusted; behind a CDN, add its ranges too |
| `TURNSTILE_ENABLE`, `TURNSTILE_SITE_KEY`, `TURNSTILE_SECRET_KEY` | off | `yes` with both keys puts a Cloudflare Turnstile check on the sign-in, organization and invitation forms |
| `SSO_GOOGLE_CLIENT_ID`, `SSO_GOOGLE_CLIENT_SECRET`, `SSO_GOOGLE_DOMAIN` | off | "Sign in with Google": the OAuth client of a Google Cloud project, optionally limited to one Workspace domain; needs `APP_URL` |
| `SSO_ENTRA_TENANT_ID`, `SSO_ENTRA_CLIENT_ID`, `SSO_ENTRA_CLIENT_SECRET` | off | "Sign in with Microsoft" for one Microsoft Entra ID tenant; needs `APP_URL` |
| `NOTIFY_PRIVATE_TARGETS` | `no` | `yes` lets notification channels reach private addresses, for example a Zabbix server on your network |
| `TEST_INSTANCE` | `no` | `yes` turns on limits meant for a public demo instance |

Every setting, the reverse proxy, backups and upgrades are described in the
[configuration guide](https://github.com/lukmorawski/driftband/blob/main/docs/CONFIGURATION.md).

Put Driftband behind a reverse proxy that terminates HTTPS (nginx, Apache,
HAProxy, Traefik: the guide has an example for each). The application has
no TLS of its own, by design, and should not be used over plain HTTP, not
even inside a private network.

New people join an organization only through an invitation link. A
platform administrator can also turn off creating organizations, which
leaves a sign-in form and nothing else for visitors.

## Security

- Runs as a non-root user (uid 10001) and needs **no Linux capabilities**:
  fping uses unprivileged ICMP sockets (`net.ipv4.ping_group_range`, Docker's
  default for containers, set explicitly above).
- Works with a read-only root filesystem and `no-new-privileges`.
- Every image ships with an SBOM and build provenance attestations
  (`docker buildx imagetools inspect lukmorawski/driftband:0.2.0 --format '{{ json .SBOM }}'`).
- Argon2id passwords, single sign-on with OpenID Connect (PKCE, verified
  ID tokens, accounts connected explicitly and never matched by email),
  two-factor authentication (security keys, passkeys, TOTP), rate-limited
  sign-in, encrypted notification channels,
  SSRF-checked webhooks, an audit log of every action, and an automated
  security test suite covering every API endpoint.

## Health check

`GET /api/health` answers `200` with `{"status":"ok","database":"ok"}` when
the application is serving and its database answers, and `503` otherwise.
It needs no session; point your load balancer and monitoring at it. The
image's built-in `HEALTHCHECK` uses the same endpoint. `docker run --rm
lukmorawski/driftband:0.2.0 --version` prints the version.

## Responsible use

Probe only hosts and networks that you own or have permission to measure.
The software comes without warranty; the author accepts no responsibility
for misuse or hostile use of it.
