#!/bin/sh
set -eu
PREFIX=${NETBOT_PREFIX:-"$HOME/Library/Application Support/Netbot"}
BIN=${NETBOT_BIN:-"$HOME/.local/bin"}
if command -v launchctl >/dev/null 2>&1; then launchctl bootout "gui/$(id -u)/com.netbot.watch" >/dev/null 2>&1 || true; fi
rm -f "$BIN/netbot" "$BIN/netbot-watch"
rm -f "$PREFIX/service.loaded"
rm -rf "$PREFIX/current" "$PREFIX/versions" "$PREFIX/run" "$PREFIX/logs"
echo "Removed Netbot runtime integration; retained $PREFIX/config and $PREFIX/state."
