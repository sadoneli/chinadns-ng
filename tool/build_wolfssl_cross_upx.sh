#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

ZIG_BIN="${ZIG_BIN:-}"
if [[ -z "$ZIG_BIN" ]]; then
  if command -v zig >/dev/null 2>&1; then
    ZIG_BIN="$(command -v zig)"
  elif [[ -x /tmp/zig/zig-linux-x86_64-0.10.1/zig ]]; then
    ZIG_BIN="/tmp/zig/zig-linux-x86_64-0.10.1/zig"
  else
    echo "missing zig; set ZIG_BIN=/path/to/zig (or install zig)"; exit 1
  fi
fi

UPX_424_BIN="${UPX_424_BIN:-upx-4.2.4}"

command -v "$UPX_424_BIN" >/dev/null 2>&1 || { echo "missing $UPX_424_BIN"; exit 1; }

OUT_AARCH64="chinadns-ng+wolfssl@aarch64-linux-musl@generic+v8a@fast+lto"
OUT_ARM_V7A="chinadns-ng+wolfssl@arm-linux-musleabi@generic+v7a@fast+lto"
OUT_ARM_V5TE="chinadns-ng+wolfssl@arm-linux-musleabi@generic+v5te+soft_float@fast+lto"

build_one() {
  local target="$1"
  local cpu="$2"
  local out="$3"
  "$ZIG_BIN" build \
    -Dwolfssl=true \
    -Dtarget="$target" \
    -Dcpu="$cpu" \
    -Dmode=fast \
    -Dlto=true \
    -Dstrip=true
  cp -f "zig-out/bin/$out" "dist/$out"
  chmod +x "dist/$out"
}

mkdir -p dist

echo "[build] $OUT_AARCH64"
build_one aarch64-linux-musl 'generic+v8a' "$OUT_AARCH64"

echo "[build] $OUT_ARM_V7A"
build_one arm-linux-musleabi 'generic+v7a' "$OUT_ARM_V7A"

echo "[build] $OUT_ARM_V5TE"
build_one arm-linux-musleabi 'generic+v5te+soft_float' "$OUT_ARM_V5TE"

OUT_AARCH64_UPX="${OUT_AARCH64}.upx"
OUT_ARM_V7A_UPX="${OUT_ARM_V7A}.upx"
OUT_ARM_V5TE_UPX="${OUT_ARM_V5TE}.upx"

cp -f "dist/$OUT_AARCH64" "dist/$OUT_AARCH64_UPX"
cp -f "dist/$OUT_ARM_V7A" "dist/$OUT_ARM_V7A_UPX"
cp -f "dist/$OUT_ARM_V5TE" "dist/$OUT_ARM_V5TE_UPX"

echo "[upx] $OUT_ARM_V7A_UPX (upx-4.2.4)"
"$UPX_424_BIN" --best "dist/$OUT_ARM_V7A_UPX"

echo "[upx] $OUT_ARM_V5TE_UPX (upx-4.2.4)"
"$UPX_424_BIN" --best "dist/$OUT_ARM_V5TE_UPX"

echo "[upx] $OUT_AARCH64_UPX (upx-4.2.4)"
"$UPX_424_BIN" --best "dist/$OUT_AARCH64_UPX"

sha256sum \
  "dist/$OUT_AARCH64" \
  "dist/$OUT_ARM_V7A" \
  "dist/$OUT_ARM_V5TE" \
  "dist/$OUT_AARCH64_UPX" \
  "dist/$OUT_ARM_V7A_UPX" \
  "dist/$OUT_ARM_V5TE_UPX" \
  > dist/SHA256SUMS

echo "[done] outputs:"
ls -la \
  "dist/$OUT_AARCH64" \
  "dist/$OUT_ARM_V7A" \
  "dist/$OUT_ARM_V5TE" \
  "dist/$OUT_AARCH64_UPX" \
  "dist/$OUT_ARM_V7A_UPX" \
  "dist/$OUT_ARM_V5TE_UPX" \
  dist/SHA256SUMS
