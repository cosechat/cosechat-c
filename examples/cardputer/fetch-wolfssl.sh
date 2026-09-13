#!/usr/bin/env sh
# Fetch a wolfSSL >= 5.8 tree into lib/wolfssl so PlatformIO can build it as a
# local library. The PlatformIO registry package stops at 5.7.2, which has no
# ML-KEM (wolfssl/wolfcrypt/wc_mlkem.h), so `lib_deps = wolfssl/wolfssl`
# cannot build cosechat.
#
# Run once before `pio run`; re-run to switch versions.
set -eu

HERE="$(cd "$(dirname "$0")" && pwd)"
VERSION="${WOLFSSL_VERSION:-v5.9.0-stable}"
DEST="$HERE/lib/wolfssl"

if [ ! -f "$DEST/wolfssl/wolfcrypt/wc_mlkem.h" ]; then
  TMP="$(mktemp -d)"
  trap 'rm -rf "$TMP"' EXIT

  git clone --depth 1 --branch "$VERSION" \
    https://github.com/wolfSSL/wolfssl.git "$TMP/wolfssl"

  mkdir -p "$DEST"
  # PlatformIO does not follow symlinked directories inside a library, so copy.
  cp -R "$TMP/wolfssl/src" "$DEST/src"
  cp -R "$TMP/wolfssl/wolfcrypt" "$DEST/wolfcrypt"
  cp -R "$TMP/wolfssl/wolfssl" "$DEST/wolfssl"

  # cosechat only needs wolfcrypt, not the TLS layer.
  cat > "$DEST/library.json" <<'JSON'
{
  "name": "wolfssl",
  "version": "5.9.0",
  "build": {
    "srcDir": ".",
    "srcFilter": ["+<wolfcrypt/src/**/*.c>"],
    "includeDir": "."
  }
}
JSON
fi

# The library's own sources also need the settings, and they cannot see the
# sketch's include/ directory. Keep a copy in sync with the one next door.
cp "$HERE/include/user_settings.h" "$DEST/user_settings.h"

echo "wolfSSL installed in $DEST (from $VERSION)"
