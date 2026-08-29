#!/bin/sh
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
VERSION=$(PYTHONPATH="$ROOT" python3 -c 'from netbot.version import __version__; print(__version__)')
exec python3 "$ROOT/scripts/build_release.py" "$ROOT" "$VERSION"
