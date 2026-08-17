#!/bin/bash
# Assembles tools/ur-bridge.html from its pieces. All libraries are embedded
# verbatim so the page is fully self-contained (airgap tool, no fetches).
set -euo pipefail

# run from anywhere; sources live next to this script, output one level up
BUILD="$(cd "$(dirname "$0")" && pwd)"
TOOLS="$(dirname "$BUILD")"
OUT="$TOOLS/ur-bridge.html"

{
  cat "$BUILD/head.html"

  echo '<script>'
  echo '/* ===== embedded test vectors (tools/test-vectors.json) ===== */'
  printf 'var TEST_VECTORS = '
  cat "$TOOLS/test-vectors.json"
  echo ';'
  echo '</script>'

  echo '<script>'
  echo '/* ===== library: ur.js (BC-UR port, see tools/ur.js) ===== */'
  cat "$TOOLS/ur.js"
  echo '</script>'

  echo '<script>'
  echo '/* ===== library: jsQR (QR decode fallback) — embedded verbatim ===== */'
  cat "$BUILD/jsQR.js"
  echo ''
  echo '</script>'

  echo '<script>'
  echo '/* ===== library: qrcode-generator (QR encode, global `qrcode`) — embedded verbatim ===== */'
  cat "$BUILD/qrcode-gen.js"
  echo ''
  echo '</script>'

  echo '<script>'
  echo '/* ===== application ===== */'
  cat "$BUILD/app.js"
  echo '</script>'

  echo '</body>'
  echo '</html>'
} > "$OUT"

echo "wrote $OUT ($(wc -c < "$OUT") bytes)"
# Sanity: balanced script tags
OPEN=$(grep -c '^<script>' "$OUT")
CLOSE=$(grep -c '^</script>' "$OUT")
echo "script tags: $OPEN open / $CLOSE close"
