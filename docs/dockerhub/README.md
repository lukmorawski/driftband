# Driftband

**Self-hosted smoke graphs for ICMP latency and packet loss. SmokePing, reimagined.**

Driftband pings your hosts with fping and draws the whole distribution of
round-trip times as percentile bands, with a median line coloured by packet
loss. Everything is configured in the browser: a host tree with drag and drop,
probe profiles, organizations and roles, two-factor sign-in, notifications
(Telegram, Slack, Microsoft Teams, email) with flap detection, an audit log of
every action, and a one-paste import of your SmokePing Targets.

![Driftband smoke graphs](https://driftband.app/assets/img/shot-portale-dark.webp)

- Website: https://driftband.app
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
    image: lukmorawski/driftband:0.1.0
    restart: unless-stopped
    depends_on:
      db:
        condition: service_healthy
    environment:
      DATABASE_URL: postgres://driftband:${DB_PASSWORD:?set DB_PASSWORD in .env}@db:5432/driftband?sslmode=disable
      SECRET_KEY: ${SECRET_KEY:?set SECRET_KEY in .env}
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
| `TEST_INSTANCE` | `no` | `yes` turns on limits meant for a public demo instance |

Every setting, the reverse proxy, backups and upgrades are described in the
[configuration guide](https://github.com/lukmorawski/driftband/blob/main/docs/CONFIGURATION.md).

Put Driftband behind a reverse proxy with HTTPS: session cookies are marked
`Secure` automatically.

## Security

- Runs as a non-root user (uid 10001) and needs **no Linux capabilities**:
  fping uses unprivileged ICMP sockets (`net.ipv4.ping_group_range`, Docker's
  default for containers, set explicitly above).
- Works with a read-only root filesystem and `no-new-privileges`.
- Every image ships with an SBOM and build provenance attestations
  (`docker buildx imagetools inspect lukmorawski/driftband:0.1.0 --format '{{ json .SBOM }}'`).
- Argon2id passwords, two-factor authentication (security keys, passkeys,
  TOTP), rate-limited sign-in, encrypted notification channels,
  SSRF-checked webhooks, an audit log of every action, and an automated
  security test suite covering every API endpoint.

## Health check

The image has a built-in `HEALTHCHECK` (`GET /robots.txt`). `docker run --rm
lukmorawski/driftband:0.1.0 --version` prints the version.
