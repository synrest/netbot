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
  Darwin) BACKEND=launchd; command -v launchctl >/dev/null || { echo "ERROR: launchctl is required on macOS." >&2; exit 1; } ;;
  Linux)
    if command -v systemctl >/dev/null 2>&1 && { [ -d /run/systemd/system ] || systemctl --user show-environment >/dev/null 2>&1; }; then BACKEND=systemd
    elif command -v rc-service >/dev/null 2>&1 && { command -v openrc-run >/dev/null 2>&1 || [ -x /sbin/openrc ]; }; then BACKEND=openrc
    elif [ "$NO_SERVICE" -eq 1 ]; then BACKEND=unsupported
    else echo "ERROR: unsupported Linux supervisor; systemd user manager or OpenRC is required." >&2; exit 1
    fi
    ;;
  *) echo "ERROR: supported deployment systems are macOS and Linux." >&2; exit 1 ;;
esac
command -v "$PYTHON" >/dev/null || { echo "ERROR: Python >= 3.10 is required." >&2; exit 1; }
"$PYTHON" -c 'import sys; sys.exit(0 if sys.version_info >= (3,10) else 1)' || { echo "ERROR: Python >= 3.10 is required." >&2; exit 1; }
"$PYTHON" -c 'import venv, ensurepip' >/dev/null 2>&1 || {
  echo "ERROR: Python venv/ensurepip support is required; install the platform package providing it (for example python3-venv on Debian)." >&2
  exit 1
}
command -v tailscale >/dev/null || { echo "ERROR: Tailscale CLI is required; install it separately." >&2; exit 1; }
command -v ssh >/dev/null || { echo "ERROR: OpenSSH client is required." >&2; exit 1; }
tailscale version >/dev/null 2>&1 || { echo "ERROR: Tailscale CLI is not accessible." >&2; exit 1; }

VERSION=$("$PYTHON" -c 'import sys; sys.path.insert(0, sys.argv[1]); from netbot.version import __version__; print(__version__)' "$ROOT")
VERSIONS="$PREFIX/versions"
LOGS="$PREFIX/logs"
[ "$(uname -s)" = Darwin ] && LOGS="$HOME/Library/Logs/Netbot"
mkdir -p "$VERSIONS" "$PREFIX/config" "$PREFIX/state" "$PREFIX/run" "$PREFIX/generated" "$LOGS" "$BIN"
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
mkdir -p "$STAGE/systemd" "$STAGE/openrc"
cp "$ROOT/systemd/netbot-watch.service" "$STAGE/systemd/netbot-watch.service"
cp "$ROOT/openrc/netbot-watch" "$STAGE/openrc/netbot-watch"
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
if [ "$NO_SERVICE" -eq 0 ] && [ "$BACKEND" = launchd ]; then
  launchctl bootout "gui/$(id -u)/com.netbot.watch" >/dev/null 2>&1 || true
  launchctl bootstrap "gui/$(id -u)" "$PREFIX/current/launchd/com.netbot.watch.plist"
  touch "$PREFIX/service.loaded"
fi
if [ "$NO_SERVICE" -eq 0 ] && [ "$BACKEND" = systemd ]; then
  mkdir -p "$HOME/.config/systemd/user"
  sed -e "s|__NETBOT_BIN__|$BIN|g" -e "s|__NETBOT_PREFIX__|$PREFIX|g" \
    "$PREFIX/current/systemd/netbot-watch.service" > "$HOME/.config/systemd/user/netbot-watch.service"
  if systemctl --user daemon-reload && systemctl --user enable --now netbot-watch.service; then
    touch "$PREFIX/service.loaded"
  else
    echo "WARNING: Netbot installed, but systemd user service activation was not completed." >&2
  fi
fi
if [ "$NO_SERVICE" -eq 0 ] && [ "$BACKEND" = openrc ]; then
  mkdir -p "$PREFIX/install/openrc"
  sed -e "s|__NETBOT_BIN__|$BIN|g" -e "s|__NETBOT_PREFIX__|$PREFIX|g" \
    "$PREFIX/current/openrc/netbot-watch" > "$PREFIX/install/openrc/netbot-watch"
  chmod 755 "$PREFIX/install/openrc/netbot-watch"
  echo "WARNING: OpenRC service template prepared at $PREFIX/install/openrc/netbot-watch; installing /etc/init.d/netbot-watch requires explicit administrator action." >&2
fi
echo "Installed Netbot $VERSION at $PREFIX"
