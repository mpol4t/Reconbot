#!/bin/sh
set -eu
resource_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
iconset_dir=$(mktemp -d "${TMPDIR:-/tmp}/reconbot-icons.XXXXXX")/ReconBot.iconset
mkdir -p "$iconset_dir"
trap 'rm -rf "$(dirname "$iconset_dir")"' EXIT
for size in 16 32 128 256 512; do
  sips -z "$size" "$size" "$resource_dir/reconbot-icon.png" --out "$iconset_dir/icon_${size}x${size}.png" >/dev/null
  doubled=$((size * 2))
  sips -z "$doubled" "$doubled" "$resource_dir/reconbot-icon.png" --out "$iconset_dir/icon_${size}x${size}@2x.png" >/dev/null
done
iconutil -c icns "$iconset_dir" -o "$resource_dir/reconbot-icon.icns"
mkdir -p "$resource_dir/icons"
for size in 16 32 48 64 128 256 512; do
  sips -z "$size" "$size" "$resource_dir/reconbot-icon.png" --out "$resource_dir/icons/${size}x${size}.png" >/dev/null
done
