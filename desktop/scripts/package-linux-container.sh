#!/bin/sh
# Runs inside a disposable Linux build container, with the checkout read-only.
set -eu
export ELECTRON_CACHE=/package/cache/electron
export ELECTRON_BUILDER_CACHE=/package/cache/electron-builder
if [ ! -x /tmp/backend-venv/bin/python ]; then
  apt-get update -qq
  apt-get install -y -qq python3 python3-venv libpython3.11 build-essential libgtk-3-0 libnss3 libasound2 libgbm1 xvfb > /tmp/apt.log
  python3 -m venv /tmp/backend-venv
  /tmp/backend-venv/bin/pip install -q dnspython requests 'urllib3>=2.8,<3' PyYAML 'tldextract>=5.3,<6' 'pyinstaller>=6.22,<7'
fi
RECONBOT_BACKEND_BUILD_DIR=/package/build /tmp/backend-venv/bin/python /source/desktop/scripts/build-backend.py
/package/build/backend/reconbot-backend/reconbot-backend -m reconbot --check-runtime
mkdir -p /tmp/desktop-build
cp /source/desktop/package.json /source/desktop/package-lock.json /tmp/desktop-build/
cp -R /source/desktop/out /source/desktop/resources /source/desktop/scripts /tmp/desktop-build/
ln -s /package/build /tmp/desktop-build/build
cd /tmp/desktop-build
npm ci --no-audit
RECONBOT_LICENSE_ROOT=/source RECONBOT_PYTHON=/tmp/backend-venv/bin/python RECONBOT_LICENSE_OUTPUT=/package/build/licenses node scripts/build-licenses.cjs
# Reuse a cached official runtime only after checking its release checksum.
electron_archive=$(/tmp/backend-venv/bin/python - <<'PY_CACHE'
import hashlib, json, subprocess
from pathlib import Path
version = json.loads(Path('node_modules/electron/package.json').read_text())['version']
arch = subprocess.check_output(['node', '-p', 'process.arch'], text=True).strip()
if arch not in {'x64', 'arm64'}:
    raise SystemExit('Unsupported Linux packaging architecture: ' + arch)
name = f'electron-v{version}-linux-{arch}.zip'
expected = json.loads(Path('node_modules/electron/checksums.json').read_text()).get(name)
for archive in Path('/package/cache/electron').rglob(name):
    with archive.open('rb') as stream:
        actual = hashlib.file_digest(stream, 'sha256').hexdigest()
    if expected and actual == expected:
        print(archive)
        break
PY_CACHE
)
if [ -n "$electron_archive" ]; then
  ./node_modules/.bin/electron-builder --linux --publish never --config.directories.output=/package/dist --config.electronDist="$electron_archive"
else
  ./node_modules/.bin/electron-builder --linux --publish never --config.directories.output=/package/dist --config.electronDownload.cache=/package/cache/electron
fi
native_arch=$(node -p process.arch)
case "$native_arch" in
  x64) native_executable=/package/dist/linux-unpacked/reconbot ;;
  arm64) native_executable=/package/dist/linux-arm64-unpacked/reconbot ;;
  *) echo "Unsupported native smoke architecture: $native_arch" >&2; exit 1 ;;
esac
RECONBOT_SMOKE_EXECUTABLE="$native_executable" xvfb-run -a node scripts/package-smoke.cjs
cp test-results/native-smoke.json /package/native-smoke.json
RECONBOT_SMOKE_EXECUTABLE="$native_executable" RECONBOT_GRAPH_SMOKE_RESULT=/package/native-graph-smoke.json xvfb-run -a node scripts/package-graph-smoke.cjs
# Extracted AppImage can be smoke-tested even without a mounted FUSE device.

RECONBOT_SMOKE_EXECUTABLE="$native_executable" RECONBOT_SQLMAP_SMOKE_RESULT=/package/native-sqlmap-smoke.json xvfb-run -a node scripts/package-sqlmap-smoke.cjs
RECONBOT_SMOKE_EXECUTABLE="$native_executable" RECONBOT_AUTHENTICATION_SMOKE_RESULT=/package/native-authentication-smoke.json xvfb-run -a node scripts/package-authentication-smoke.cjs
