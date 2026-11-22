# syntax=docker/dockerfile:1

# ---- application binary ----
# Runs on the build machine's platform and cross-compiles for the target.
FROM --platform=$BUILDPLATFORM golang:1.27-alpine AS build
WORKDIR /src
COPY backend/go.mod backend/go.sum* ./
RUN go mod download
COPY backend/ ./
COPY VERSION /VERSION
# Release builds pass VERSION; other builds take it from the VERSION file.
ARG VERSION
ARG TARGETOS=linux
ARG TARGETARCH=amd64
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build -trimpath -ldflags="-s -w -X main.version=${VERSION:-$(cat /VERSION)}" -o /driftband .
# License texts of everything compiled into the binary: the Go toolchain and
# every module it links (fails the build if a module has no license file).
RUN mkdir -p /licenses/go \
 && cp "$(go env GOROOT)/LICENSE" "$(go env GOROOT)/PATENTS" /licenses/go/ \
 && CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go list -deps -f '{{with .Module}}{{if not .Main}}{{.Path}} {{.Dir}}{{end}}{{end}}' . \
    | sort -u | while read -r mod dir; do \
        mkdir -p "/licenses/go/$mod"; \
        cp "$dir"/LICENSE* "$dir"/PATENTS* "$dir"/NOTICE* "/licenses/go/$mod/" 2>/dev/null; \
        [ -n "$(ls "/licenses/go/$mod")" ] || { echo "no license file in $mod" >&2; exit 1; }; \
      done

# ---- web assets: bundled, minified, license headers kept, URLs stamped ----
# main.js and its modules become one file; every asset index.html loads is
# referenced with ?v=<content hash> so browsers and CDNs can cache it for a
# year and still see a new build immediately (scripts/web-version.sh).
FROM --platform=$BUILDPLATFORM golang:1.27-alpine AS assets
RUN go install github.com/evanw/esbuild/cmd/esbuild@v0.28.2
WORKDIR /web
COPY web/ ./
COPY scripts/web-version.sh /web-version.sh
RUN esbuild main.js --bundle --format=esm --minify --legal-comments=inline --log-level=warning \
      --outfile=main.js --allow-overwrite \
 && find . -path ./vendor -prune -o -type f \( -name '*.js' -o -name '*.css' \) ! -name main.js -print \
    | while read -r f; do \
        esbuild "$f" --minify --legal-comments=inline --log-level=warning --outfile="$f" --allow-overwrite || exit 1; \
      done \
 && sh /web-version.sh /web

# ---- runtime ----
FROM alpine:3.24

ARG VERSION=dev
ARG REVISION=unknown
ARG CREATED=unknown
LABEL org.opencontainers.image.title="Driftband" \
      org.opencontainers.image.description="Self-hosted smoke-graph latency monitor: percentile bands, packet loss, web UI, organizations, 2FA, alerts, audit log." \
      org.opencontainers.image.url="https://driftband.app" \
      org.opencontainers.image.source="https://github.com/lukmorawski/driftband" \
      org.opencontainers.image.documentation="https://github.com/lukmorawski/driftband#readme" \
      org.opencontainers.image.authors="Lukasz Morawski" \
      org.opencontainers.image.vendor="Driftband" \
      org.opencontainers.image.licenses="AGPL-3.0-or-later" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${REVISION}" \
      org.opencontainers.image.created="${CREATED}"

# fping needs no privileges: it uses unprivileged ICMP sockets, allowed by
# net.ipv4.ping_group_range (Docker's default for containers). Alpine ships it
# with the cap_net_raw file capability, which would make it fail to start
# under `cap_drop: ALL`, so that capability is removed. The app runs as a
# fixed non-root user and only reads its own files. The base image's
# packages are upgraded so a build picks up Alpine's security fixes.
RUN apk upgrade --no-cache \
 && apk add --no-cache fping ca-certificates tzdata \
 && apk add --no-cache --virtual .setcap libcap-utils \
 && setcap -r /usr/sbin/fping \
 && apk del .setcap \
 && addgroup -S -g 10001 driftband \
 && adduser -S -D -H -u 10001 -G driftband -s /sbin/nologin driftband

WORKDIR /app
COPY --from=build /driftband /usr/local/bin/driftband
COPY --from=assets /web/ /app/web/
COPY LICENSE NOTICE /usr/share/licenses/driftband/
COPY licenses/ /usr/share/licenses/driftband/third-party/
COPY --from=build /licenses/go/ /usr/share/licenses/driftband/third-party/go/
ENV LISTEN=:8080 WEB_DIR=/app/web
EXPOSE 8080
USER 10001:10001

HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 \
  CMD wget -q -O /dev/null "http://127.0.0.1:${LISTEN##*:}/api/health" || exit 1

ENTRYPOINT ["driftband"]
