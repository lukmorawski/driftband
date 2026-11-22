# Configuration

Driftband is configured with environment variables. With Docker Compose
they live in a `.env` file next to `docker-compose.yml`; Compose reads it
automatically. Start from [`.env.example`](../.env.example):

```bash
cp .env.example .env
chmod 600 .env
```

Everything else (hosts, probe profiles, alerts, users) is set up in the
web interface.

## Settings in `.env`

| Variable | Required | Default | Purpose |
|---|---|---|---|
| `DB_PASSWORD` | yes | | Password of the PostgreSQL user, used by both containers. Generate one: `openssl rand -hex 24`. |
| `SECRET_KEY` | recommended | generated and stored in the database | Master key (32 bytes, hex or base64) that encrypts notification channels and two-factor secrets. Generate one: `openssl rand -hex 32`. |
| `APP_URL` | behind a proxy | none | Public address of the instance, for example `https://latency.example.org`. Used in notification links, and it is the address security keys and passkeys are bound to. |
| `TRUSTED_PROXIES` | behind a proxy | loopback and private ranges | Comma-separated addresses or CIDRs of the reverse proxies whose `X-Forwarded-For` and `X-Forwarded-Proto` headers are believed. |
| `TEST_INSTANCE` | no | `no` | `yes` turns on limits meant for a public demo: 10 hosts per organization, probe interval of at least 60 s, packets of at most 56 bytes. |

### `SECRET_KEY`

Set it before you add notification channels or enroll second factors, and
keep a copy somewhere safe.

- With the key in `.env`, a copy of the database alone does not reveal
  channel settings, tokens or two-factor secrets.
- Without it, Driftband generates a key on first start and keeps it in the
  database. That still keeps secrets out of API responses, but not out of
  a database dump.
- If the key is lost or changed, stored channels and second factors can no
  longer be read: channels have to be entered again, and a platform
  administrator has to reset two-factor sign-in for the affected accounts.

### `APP_URL`

Security keys and passkeys are tied to the host name in `APP_URL` (or, when
it is empty, to the host name of the request). Changing it later
invalidates every enrolled key. The host name must be a real name such as
`latency.example.org` or `localhost`, not an IP address.

### `TRUSTED_PROXIES`

The client address written to the audit log and used for rate limiting is
taken from `X-Forwarded-For` only when the request arrives from a trusted
proxy. The default trusts loopback and private ranges, which suits a proxy
on the same host or network. If the application can be reached directly
from the internet through such a range, narrow the setting to the proxy's
address. Each proxy must append the address it received the request from
(nginx: `$proxy_add_x_forwarded_for`; HAProxy: `option forwardfor`). Behind
a CDN, add the CDN's published address ranges as well.

## Settings of the application container

`docker-compose.yml` passes the values above to the application and sets
the rest itself. You only touch these when you run the image without the
provided compose file.

| Variable | Default | Purpose |
|---|---|---|
| `DATABASE_URL` | required | PostgreSQL connection string, for example `postgres://driftband:PASSWORD@db:5432/driftband?sslmode=disable`. |
| `LISTEN` | `:8080` | Address and port the HTTP server listens on. |
| `WEB_DIR` | `/app/web` | Directory of the web interface inside the image. |
| `LANDING_DIR` | none | Directory of a static website to serve under `/main`. Leave it unset unless you add your own site to the image. |

The container needs the sysctl `net.ipv4.ping_group_range` to cover its
group (Docker's default; the compose file sets it explicitly) so that fping
can send ICMP without privileges. It needs no Linux capabilities and works
with a read-only root filesystem.

## Reverse proxy and HTTPS

Run Driftband behind a reverse proxy that terminates HTTPS. When a trusted
proxy reports `X-Forwarded-Proto: https`, the session cookie is marked
`Secure`. A minimal nginx location:

```nginx
location / {
    proxy_pass http://127.0.0.1:8080;
    proxy_set_header Host $host;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;
}
```

Then set `APP_URL` to the public address. To keep the application off
public interfaces, change the port mapping in `docker-compose.yml` to
`"127.0.0.1:8080:8080"`.

## First steps

1. Open the address and register: the first registration creates an
   organization and makes you its owner.
2. Add folders and hosts on the dashboard, or import a SmokePing `Targets`
   section in Settings, Import.
3. Enable two-factor sign-in in Settings, Account.
4. Add a notification channel and an alert rule in Settings,
   Notifications. The FAQ in the application walks through each channel
   type.

## Platform administrator

A platform administrator sees every organization, can block or delete
organizations and users, reset two-factor sign-in and set host limits.
The flag can only be set in the database, never through the web interface
or the API:

```bash
docker compose exec db psql -U driftband -c \
  "UPDATE users SET is_superadmin = true WHERE email = 'you@example.org'"
```

Sign out and in again; an Admin entry appears in the navigation.

## Data and retention

Each organization keeps 1, 2 or 3 years of measurements (Settings, Data retention);
older data is deleted daily. One host probed once a minute needs roughly
190 MB per year. The Usage view shows the current size and a forecast.

## Backups

All state is in PostgreSQL (plus `SECRET_KEY` in `.env`). A consistent
backup while the stack is running:

```bash
docker compose exec -T db pg_dump -U driftband -d driftband -Fc > driftband.dump
```

Restore into an empty database of the same PostgreSQL version:

```bash
docker compose exec -T db pg_restore -U driftband -d driftband < driftband.dump
```

Keep `.env` with the dump: without the same `SECRET_KEY` the restored
channels and second factors cannot be read.

## Upgrading

**Driftband.** Change the image tag in `docker-compose.yml` (or pull the
repository) and run `docker compose up -d`. The schema is upgraded at
start. Read the [changelog](../CHANGELOG.md) first.

**PostgreSQL major version.** A new major version cannot read the old data
directory. After changing the `postgres` image tag, and before the next
`docker compose up`, run this from a checkout of the repository while the
old database container is still running:

```bash
scripts/upgrade-postgres.sh
```

It stops the application, dumps the database to `backups/`, starts the new
PostgreSQL, restores the dump, compares the row count of every table and
starts the application again. The old data and the dump are kept until you
remove them.
