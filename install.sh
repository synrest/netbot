#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
PREFIX=${NETBOT_PREFIX:-"$HOME/Library/Application Support/Netbot"}
BIN=${NETBOT_BIN:-"$HOME/.local/bin"}
PYTHON=${PYTHON:-python3}
NO_SERVICE=0
for arg in "$@"; do
  case "$arg" in
    --dev) ;;
    --no-service) NO_SERVICE=1 ;;
    *) echo "usage: ./install.sh [--dev] [--no-service]" >&2; exit 2 ;;
  esac
done

case "$(uname -s)" in
  Darwin) command -v launchctl >/dev/null || { echo "ERROR: launchctl is required on macOS." >&2; exit 1; } ;;
  *) echo "ERROR: production deployment currently targets macOS; use --dev for local development." >&2 ;;
esac
command -v "$PYTHON" >/dev/null || { echo "ERROR: Python >= 3.10 is required." >&2; exit 1; }
"$PYTHON" -c 'import sys; sys.exit(0 if sys.version_info >= (3,10) else 1)' || { echo "ERROR: Python >= 3.10 is required." >&2; exit 1; }
command -v tailscale >/dev/null || { echo "ERROR: Tailscale CLI is required; install it separately." >&2; exit 1; }
command -v ssh >/dev/null || { echo "ERROR: OpenSSH client is required." >&2; exit 1; }
tailscale version >/dev/null 2>&1 || { echo "ERROR: Tailscale CLI is not accessible." >&2; exit 1; }

VERSION=$("$PYTHON" -c 'import sys; sys.path.insert(0, sys.argv[1]); from netbot.version import __version__; print(__version__)' "$ROOT")
VERSIONS="$PREFIX/versions"
mkdir -p "$VERSIONS" "$PREFIX/config" "$PREFIX/state" "$PREFIX/run" "$PREFIX/generated" "$HOME/Library/Logs/Netbot" "$BIN"
if [ ! -f "$PREFIX/config/topology.yaml" ] && [ -f "$ROOT/config/topology.yaml" ]; then cp "$ROOT/config/topology.yaml" "$PREFIX/config/topology.yaml"; fi
if [ ! -f "$PREFIX/state/netbot.sqlite3" ] && [ -f "$ROOT/state/netbot.sqlite3" ]; then cp "$ROOT/state/netbot.sqlite3" "$PREFIX/state/netbot.sqlite3"; fi

STAGE=$(mktemp -d "$VERSIONS/.stage.XXXXXX")
cleanup() { rm -rf "$STAGE"; }
trap cleanup EXIT HUP INT TERM
"$PYTHON" -m venv "$STAGE/venv"
SITE=$("$STAGE/venv/bin/python" -c 'import site; print(site.getsitepackages()[0])')
mkdir -p "$SITE"
cp -R "$ROOT/netbot" "$SITE/netbot"
mkdir -p "$STAGE/launchd"
cp "$ROOT/launchd/com.netbot.watch.plist" "$STAGE/launchd/com.netbot.watch.plist"
"$STAGE/venv/bin/python" - "$STAGE/launchd/com.netbot.watch.plist" "$PREFIX" "$BIN" <<'PY'
import plistlib, sys
path, prefix, bin_dir = sys.argv[1:]
with open(path, "rb") as stream:
    data = plistlib.load(stream)
data["ProgramArguments"] = [bin_dir + "/netbot-watch"]
data["WorkingDirectory"] = prefix
data["EnvironmentVariables"] = {"PATH": "/usr/local/bin:/usr/bin:/bin"}
data["StandardOutPath"] = prefix + "/logs/watch.log"
data["StandardErrorPath"] = prefix + "/logs/watch.err.log"
with open(path, "wb") as stream:
    plistlib.dump(data, stream, sort_keys=False)
PY
mkdir -p "$PREFIX/logs"
FINAL="$VERSIONS/$VERSION"
if [ -e "$FINAL" ]; then rm -rf "$FINAL"; fi
mv "$STAGE" "$FINAL"
ln -sfn "$FINAL" "$PREFIX/current"
mkdir -p "$BIN"
cat > "$BIN/netbot" <<EOF
#!/bin/sh
set -eu
export NETBOT_PREFIX="$PREFIX"
cd "$PREFIX"
exec "$PREFIX/current/venv/bin/python" -m netbot.cli "\$@"
EOF
cat > "$BIN/netbot-watch" <<EOF
#!/bin/sh
set -eu
export NETBOT_PREFIX="$PREFIX"
cd "$PREFIX"
exec "$PREFIX/current/venv/bin/python" -m netbot.watcher "\$@"
EOF
chmod 755 "$BIN/netbot" "$BIN/netbot-watch"
if [ "$NO_SERVICE" -eq 0 ] && [ "$(uname -s)" = Darwin ]; then
  launchctl bootout "gui/$(id -u)/com.netbot.watch" >/dev/null 2>&1 || true
  launchctl bootstrap "gui/$(id -u)" "$PREFIX/current/launchd/com.netbot.watch.plist"
  touch "$PREFIX/service.loaded"
fi
echo "Installed Netbot $VERSION at $PREFIX"
