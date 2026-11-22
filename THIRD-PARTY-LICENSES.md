# Third-party components

Driftband is licensed under **AGPL-3.0-or-later** (see `LICENSE`). It uses the
following independent third-party components, each under its own permissive
license. None of them imposes copyleft on Driftband; AGPL is Driftband's own
choice.

| Component | Role | License | Where |
|-----------|------|---------|-------|
| [uPlot](https://github.com/leeoniya/uPlot) | charting (canvas) | MIT | `web/vendor/uPlot.*` (bundled) |
| [qrcode-generator](https://github.com/kazuhikoarase/qrcode-generator) | TOTP enrollment QR codes | MIT | `web/vendor/qrcode.js` (bundled) |
| [jackc/pgx](https://github.com/jackc/pgx) | PostgreSQL driver (Go) | MIT | Go module dependency |
| [golang.org/x/crypto](https://pkg.go.dev/golang.org/x/crypto) | Argon2id password hashing | BSD-3-Clause | Go module dependency |
| [go-webauthn/webauthn](https://github.com/go-webauthn/webauthn) | security keys and passkeys (WebAuthn) | BSD-3-Clause | Go module dependency |
| [golang.org/x/image](https://pkg.go.dev/golang.org/x/image) | profile pictures: WebP decoding and scaling | BSD-3-Clause | Go module dependency |
| WebAuthn dependencies ([go-webauthn/x](https://github.com/go-webauthn/x), [fxamacker/cbor](https://github.com/fxamacker/cbor), [x448/float16](https://github.com/x448/float16), [google/go-tpm](https://github.com/google/go-tpm), [google/uuid](https://github.com/google/uuid), [golang-jwt/jwt](https://github.com/golang-jwt/jwt), [go-viper/mapstructure](https://github.com/go-viper/mapstructure), [tinylib/msgp](https://github.com/tinylib/msgp), [philhofer/fwd](https://github.com/philhofer/fwd)) | attestation formats, CBOR, metadata | BSD-3-Clause / MIT / Apache-2.0 | Go module dependencies |
| Other Go modules ([jackc/puddle](https://github.com/jackc/puddle), [pgpassfile](https://github.com/jackc/pgpassfile), [pgservicefile](https://github.com/jackc/pgservicefile), [golang.org/x/sync](https://pkg.go.dev/golang.org/x/sync), [x/sys](https://pkg.go.dev/golang.org/x/sys), [x/text](https://pkg.go.dev/golang.org/x/text)) | pgx dependencies | MIT / BSD-3-Clause | Go module dependencies |
| [Go](https://go.dev) standard library and runtime | compiled into the binary | BSD-3-Clause | Go toolchain |
| [fping](https://github.com/schweikert/fping) | ICMP prober | BSD-style (Stanford) | invoked as a separate process; bundled in the Docker image |
| [PostgreSQL](https://www.postgresql.org/) | database | PostgreSQL License (permissive) | separate container image |
| [Inter](https://github.com/rsms/inter) | UI font | SIL OFL 1.1 | `web/vendor/fonts/` (bundled, self-hosted) |
| [Alpine Linux](https://alpinelinux.org/) base image | runtime OS | mixed (musl MIT, BusyBox GPL-2.0, …) | Docker base image - *mere aggregation* |
| [esbuild](https://github.com/evanw/esbuild) | minifies the web assets during the image build | MIT | build tool only, not distributed |

## Compliance notes

- **fping** is invoked at arm's length (`exec`), not linked. The Docker image
  redistributes the fping binary; its BSD-style notice is retained via the
  upstream package metadata in the image. fping is **not** GPL.
- **PostgreSQL** runs as a separate official container image and is not linked
  into Driftband; it keeps its own permissive license.
- **Alpine base image** carries its own component licenses (including GPL-2.0
  BusyBox). Shipping an application on a Linux base image is *mere aggregation*
  and does not affect Driftband's license.
- **Inter** is bundled as WOFF2 subsets (latin, latin-ext) in
  `web/vendor/fonts/`, self-hosted so the application makes no third-party
  requests. SIL Open Font License 1.1 (copyright The Inter Project Authors);
  the fonts are used unmodified and not sold on their own.
- **License texts**: `licenses/` holds the texts for the bundled web
  components (uPlot, qrcode-generator, Inter). The container image carries
  them, Driftband's `LICENSE` and `NOTICE`, and the license files of every Go
  module compiled into the binary (collected at build time) under
  `/usr/share/licenses/driftband/`.
- The **smoke-graph concept** is reimplemented from SmokePing's idea, not its
  code. See `NOTICE`.
