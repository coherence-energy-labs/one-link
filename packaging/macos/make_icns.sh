#!/usr/bin/env bash
# Generate a macOS multi-resolution .icns from the PNG family.
#
# Only built-in macOS tools (sips, iconutil) — no Pillow, no Inkscape,
# no homebrew dependency. Runs at CI time on the macOS runner so the
# repo never has to carry a pre-generated .icns next to the PNGs
# (which would drift the moment somebody touched the source PNG and
# forgot the regeneration step).
#
# Output:
#   The output path passed by build_binary.py, or build/one-glyph.icns.
#
# Source:
#   src/one_link/web/assets/one-glyph-512.png  (preferred high-res)
#   src/one_link/web/assets/one-glyph.png      (fallback)
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
ASSETS="$REPO_ROOT/src/one_link/web/assets"
OUT="${1:-$REPO_ROOT/build/one-glyph.icns}"

# Pick the highest-quality source PNG available.
SRC=""
for candidate in "$ASSETS/one-glyph-512.png" "$ASSETS/one-glyph-256.png" "$ASSETS/one-glyph.png"; do
  if [ -f "$candidate" ]; then
    SRC="$candidate"
    break
  fi
done
if [ -z "$SRC" ]; then
  echo "[icns] FATAL: no source PNG in $ASSETS" >&2
  exit 1
fi
echo "[icns] source PNG: $SRC"

TMP="$(mktemp -d)"
ISET="$TMP/one-glyph.iconset"
mkdir -p "$ISET"

# Apple's required size matrix for a .iconset. Each filename pattern
# corresponds to a "logical" size + a "@2x" Retina variant.
declare -a SIZES=(
  "16:icon_16x16.png"
  "32:icon_16x16@2x.png"
  "32:icon_32x32.png"
  "64:icon_32x32@2x.png"
  "128:icon_128x128.png"
  "256:icon_128x128@2x.png"
  "256:icon_256x256.png"
  "512:icon_256x256@2x.png"
  "512:icon_512x512.png"
  "1024:icon_512x512@2x.png"
)

for pair in "${SIZES[@]}"; do
  px="${pair%%:*}"
  name="${pair##*:}"
  sips -z "$px" "$px" "$SRC" --out "$ISET/$name" > /dev/null
done

mkdir -p "$(dirname "$OUT")"
iconutil -c icns -o "$OUT" "$ISET"
echo "[icns] wrote $OUT ($(wc -c < "$OUT") bytes)"
rm -rf "$TMP"
