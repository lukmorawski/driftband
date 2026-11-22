# Driftband

[![CI](https://github.com/lukmorawski/driftband/actions/workflows/ci.yml/badge.svg)](https://github.com/lukmorawski/driftband/actions/workflows/ci.yml)
[![Docker image](https://img.shields.io/docker/v/lukmorawski/driftband?sort=semver&label=docker)](https://hub.docker.com/r/lukmorawski/driftband)
[![License: AGPL v3](https://img.shields.io/badge/license-AGPL--3.0--or--later-blue.svg)](LICENSE)

**Self-hosted smoke graphs for ICMP latency and packet loss.**

Driftband pings your hosts on a schedule and draws every round-trip time as
shaded percentile bands around a median line coloured by packet loss, the
picture made famous by [SmokePing](https://oss.oetiker.ch/smokeping/).
It runs as one container next to PostgreSQL and is configured entirely in
the browser.

![Driftband smoke graphs](https://driftband.app/assets/img/shot-portale-dark.webp)

- **Smoke graphs**: percentile bands, loss-coloured median, drag to zoom,
  synchronised cursors, live mode, dark and light themes.
- **Host tree** with folders, drag and drop, per-host probe profiles
  (interval, pings per cycle, packet size) and import of a SmokePing
  `Targets` configuration.
- **Alerts** on packet loss or latency with hold times, hysteresis and flap
  suppression, delivered to Telegram, Slack, Microsoft Teams or email.
- **Organizations and roles**, invitations, two-factor sign-in (security
  keys, passkeys, TOTP), an audit log of every action.
- **Years of history**: long ranges are served from 5-minute and 1-hour
  rollups; each organization keeps 1, 2 or 3 years.

Driftband is a new implementation in Go and JavaScript. It reuses
SmokePing's idea, not its code (see [NOTICE](NOTICE)).

Website: <https://driftband.app>. To try it without installing anything,
use the public test instance at <https://test.driftband.app> (10 hosts per
organization).

## Quick start

You need Docker with the Compose plugin. Save
[`docker-compose.yml`](docs/dockerhub/README.md#quick-start) from the image
documentation, then:

```bash
printf 'DB_PASSWORD=%s\nSECRET_KEY=%s\n' "$(openssl rand -hex 24)" "$(openssl rand -hex 32)" > .env
chmod 600 .env
docker compose up -d
```

Open <http://localhost:8080>. The first person to register creates an
organization and becomes its owner; everyone else joins through an
invitation link. For anything beyond a trial, put a reverse proxy with
HTTPS in front (the application has no TLS of its own, by design) and read
the [configuration guide](docs/CONFIGURATION.md): it has examples for
nginx, Apache, HAProxy and Traefik.

To build from this repository instead of pulling the image:

```bash
cp .env.example .env     # set DB_PASSWORD and SECRET_KEY
docker compose up -d --build
```

## Documentation

| | |
|---|---|
| [Configuration](docs/CONFIGURATION.md) | every setting, reverse proxy examples, registration and invitations, Turnstile, monitoring, backups, upgrades |
| [Architecture](docs/ARCHITECTURE.md) | the components of the system and how a measurement travels through them |
| [Docker image](docs/dockerhub/README.md) | compose file, tags, container hardening |
| [Testing](TESTING.md) | the four test layers and how to run them |
| [Security testing](SECURITY-TESTING.md) | what the security suite guarantees and how to extend it |
| [Security policy](SECURITY.md) | reporting a vulnerability |
| [Contributing](CONTRIBUTING.md) | development setup, sign-off, releases |
| [Changelog](CHANGELOG.md) | what changed in each release |

## Responsible use

Driftband sends ICMP echo requests to the hosts you configure. Probe only
hosts and networks that you own or have explicit permission to measure.

The software is provided as it is, without warranty of any kind (see the
[license](LICENSE)). The author accepts no responsibility for misuse or
hostile use of it, in particular for probing or mapping networks that the
person running it does not own or administer. Whoever operates an instance
is solely responsible for how it is used and for complying with the law
and with the acceptable-use rules of their network providers.

## Support

Driftband has no paid tier and no telemetry. If it saves you time, you can
[buy me a coffee](https://buymeacoffee.com/lukmorawski).

## License

[AGPL-3.0-or-later](LICENSE). If you run a modified version as a network
service, the license asks you to offer its source to your users; the
application's footer links to the source, so point it at your fork.
Bundled third-party components are listed in
[THIRD-PARTY-LICENSES.md](THIRD-PARTY-LICENSES.md).
