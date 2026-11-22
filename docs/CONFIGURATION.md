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
| `TURNSTILE_ENABLE` | no | `no` | `yes` puts a Cloudflare Turnstile check on the sign-in, organization and invitation forms. Needs the two keys below. |
| `TURNSTILE_SITE_KEY` | with Turnstile | none | Site key of your Turnstile widget (public, sent to the browser). |
| `TURNSTILE_SECRET_KEY` | with Turnstile | none | Secret key of the widget (stays on the server). |
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

### Turnstile

[Cloudflare Turnstile](https://www.cloudflare.com/application-services/products/turnstile/)
is a challenge that keeps automated clients away from the forms anyone can
reach: signing in, creating an organization and accepting an invitation.
It is off by default. To turn it on:

1. In the Cloudflare dashboard create a Turnstile widget for the host name
   of your instance and copy its two keys.
2. Put them in `.env` and restart:

   ```
   TURNSTILE_ENABLE=yes
   TURNSTILE_SITE_KEY=0x4AAAAAAA...
   TURNSTILE_SECRET_KEY=0x4AAAAAAA...
   ```

To turn it off again set `TURNSTILE_ENABLE=no` (or remove the line) and
restart. Platform administrators see the current state in Admin, Settings.

What changes when it is on:

- The three forms show the widget and send its answer with the request.
  The server verifies the answer with Cloudflare before it looks at
  anything else: no password is checked for a request that did not pass.
- The browser loads the widget from `challenges.cloudflare.com`, and the
  server calls the same host to verify answers, so both need to reach it.
  The Content Security Policy allows that one origin for scripts and
  frames and nothing else.
- If Cloudflare cannot be reached the forms refuse requests (a check that
  cannot be made does not count as passed). Keep that in mind on networks
  without outbound access.
- A sign-in with a second factor is checked once: the request that brings
  the code or the security key presents a short-lived pass issued after
  the password was accepted.
- With `TURNSTILE_ENABLE=yes` and a missing key the application does not
  start, rather than run without the protection you asked for.

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

**The recommended and supported setup is Driftband behind a reverse proxy
that terminates HTTPS.** The application itself speaks plain HTTP only and
has no TLS support. That is deliberate: certificates, protocol versions and
ciphers belong in software built for that job, and almost every
installation already runs one.

Do not use Driftband over plain HTTP, not even inside a LAN or a corporate
network. Passwords, session cookies and two-factor codes would cross the
network readable, the session cookie cannot be marked `Secure`, and
security keys and passkeys do not work at all (browsers offer them only
over HTTPS).

Whichever proxy you use, three things matter:

1. It terminates HTTPS and forwards to the application over the loopback
   interface or a private network. Keep the application's port off public
   interfaces: in `docker-compose.yml` publish it as
   `"127.0.0.1:8080:8080"`, or do not publish it at all when the proxy
   runs in the same Docker network.
2. It sends `X-Forwarded-For` (appending the address it received the
   request from) and `X-Forwarded-Proto: https`. From the first the
   application takes the client address for the audit log and for rate
   limiting; from the second it knows to mark the session cookie `Secure`.
3. Its address is covered by `TRUSTED_PROXIES` (the default covers
   loopback and private ranges), and `APP_URL` is set to the public
   address.

The examples below assume the application listens on `127.0.0.1:8080` and
is published as `latency.example.org`. They show the parts that matter to
Driftband; add your usual TLS settings.

### nginx

```nginx
server {
    listen 443 ssl;
    http2 on;
    server_name latency.example.org;

    ssl_certificate     /etc/ssl/latency.example.org/fullchain.pem;
    ssl_certificate_key /etc/ssl/latency.example.org/privkey.pem;

    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}

server {
    listen 80;
    server_name latency.example.org;
    return 301 https://$host$request_uri;
}
```

### Apache

Needs `mod_ssl`, `mod_proxy`, `mod_proxy_http` and `mod_headers`.
`mod_proxy_http` appends the client address to `X-Forwarded-For` by itself.

```apache
<VirtualHost *:443>
    ServerName latency.example.org

    SSLEngine on
    SSLCertificateFile    /etc/ssl/latency.example.org/fullchain.pem
    SSLCertificateKeyFile /etc/ssl/latency.example.org/privkey.pem

    ProxyPreserveHost On
    ProxyPass        / http://127.0.0.1:8080/
    ProxyPassReverse / http://127.0.0.1:8080/
    RequestHeader set X-Forwarded-Proto "https"
</VirtualHost>

<VirtualHost *:80>
    ServerName latency.example.org
    Redirect permanent / https://latency.example.org/
</VirtualHost>
```

### HAProxy

```haproxy
frontend https
    mode http
    bind :443 ssl crt /etc/haproxy/certs/latency.example.org.pem alpn h2,http/1.1
    bind :80
    http-request redirect scheme https code 301 unless { ssl_fc }
    http-request set-header X-Forwarded-Proto https
    default_backend driftband

backend driftband
    mode http
    option forwardfor
    option httpchk GET /api/health
    http-check expect status 200
    server app 127.0.0.1:8080 check
```

### Traefik

With Traefik in the same Docker network the application needs no published
port. Traefik sets `X-Forwarded-For` and `X-Forwarded-Proto` itself; its
container address is in a private range, which `TRUSTED_PROXIES` trusts by
default. Add to the `driftband` service in `docker-compose.yml` (the entry
point and certificate resolver names are those of your Traefik):

```yaml
    labels:
      - traefik.enable=true
      - traefik.http.routers.driftband.rule=Host(`latency.example.org`)
      - traefik.http.routers.driftband.entrypoints=websecure
      - traefik.http.routers.driftband.tls.certresolver=letsencrypt
      - traefik.http.services.driftband.loadbalancer.server.port=8080
      - traefik.http.services.driftband.loadbalancer.healthcheck.path=/api/health
```

### Behind a CDN

If a CDN such as Cloudflare sits in front of your proxy, add the CDN's
published address ranges to `TRUSTED_PROXIES` as well; otherwise every
request appears to come from the CDN and the audit log and rate limits
lose the real client address.

## Accounts and registration

There are exactly two ways an account comes into being:

- **Creating an organization.** The sign-in page has a "Create
  organization" form. Whoever fills it in creates a new organization,
  isolated from all others, and becomes its owner.
- **An invitation.** People are added to an existing organization only
  through an invitation: an owner or admin creates a single-use link in
  Settings, Team (it names the role and expires after 48 hours), sends it,
  and the invited person sets their own email and password. There is no
  other way to join an organization: no self-registration into one, no
  account created by an administrator on someone's behalf.

A platform administrator can turn off the first way in Admin, Settings
("Allow creating organizations"). The sign-in page then shows only the
sign-in form and the server refuses to create organizations; existing
accounts and invitations work as before. On a private instance this is the
sensible state once your own organization exists: create it, make yourself
platform administrator (below), and close the instance.

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
organizations and users, reset two-factor sign-in, set host limits and
change the instance settings (Admin, Settings: whether new organizations
can be created). The flag can only be set in the database, never through
the web interface or the API:

```bash
docker compose exec db psql -U driftband -c \
  "UPDATE users SET is_superadmin = true WHERE email = 'you@example.org'"
```

Sign out and in again; an Admin entry appears in the navigation.

## Monitoring

`GET /api/health` is the endpoint for load balancers, container
orchestrators and monitoring systems. It needs no session.

| Answer | Meaning |
|---|---|
| `200` `{"status":"ok","database":"ok"}` | the application is serving requests and the database answers |
| `503` `{"status":"unavailable","database":"unreachable"}` | the application runs but cannot reach its database |
| no answer | the application is down |

```bash
curl -fsS https://latency.example.org/api/health
```

The response is never cached, reveals nothing else about the instance
(no version, no counts) and is left out of the request log. The image's
built-in `HEALTHCHECK` uses the same endpoint, so `docker ps` and
`docker inspect` show the same state. Alert on anything but `200`.

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
