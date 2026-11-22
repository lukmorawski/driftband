#!/usr/bin/env sh
# Stamps the application's asset references with ?v=<content hash>, so the
# files can be cached for a year (the server marks stamped URLs immutable)
# and a new build is picked up at once: a changed file gets a new hash and
# a new URL. Run by the image build on the minified web/ directory; the
# sources in the repository stay unstamped for development.
#
#   scripts/web-version.sh DIR
set -eu
cd "$1"

# stamp FILE ASSET...: rewrite "ASSET" and url("ASSET") references in FILE.
stamp() {
  f=$1; shift
  for asset in "$@"; do
    v=$(sha256sum "$asset" | cut -c1-10)
    sed -i -E "s#([\"'(])${asset}(\?v=[0-9a-f]+)?([\"')])#\1${asset}?v=${v}\3#g" "$f"
    echo "$f: $asset -> v=$v"
  done
}

# Fonts first (the stylesheet references them), then everything index.html loads.
stamp style.css vendor/fonts/inter-latin.woff2 vendor/fonts/inter-latin-ext.woff2
stamp index.html vendor/fonts/inter-latin.woff2 vendor/uPlot.min.css style.css \
  vendor/uPlot.iife.min.js vendor/qrcode.js main.js \
  favicon.svg favicon.ico apple-touch-icon.png
