#!/bin/sh
set -eu

# Direct, user-level bootstrap for a published GitHub Release asset.
# Usage: bootstrap.sh VERSION ARTIFACT_URL SHA256
VERSION=${1:-}
URL=${2:-}
EXPECTED=${3:-}
[ -n "$VERSION" ] && [ -n "$URL" ] && [ -n "$EXPECTED" ] || {
  echo "usage: bootstrap.sh VERSION IMMUTABLE_ZIP_URL SHA256" >&2; exit 2;
}
case "$VERSION" in *[!0-9A-Za-z.+-]*|'') echo "invalid version" >&2; exit 2;; esac
case "$EXPECTED" in *[!0-9a-fA-F]*|'') echo "invalid SHA-256" >&2; exit 2;; esac
[ "${#EXPECTED}" -eq 64 ] || { echo "invalid SHA-256" >&2; exit 2; }
command -v curl >/dev/null || { echo "curl is required" >&2; exit 1; }
command -v shasum >/dev/null || { echo "shasum is required" >&2; exit 1; }
PYTHON=${PYTHON:-python3}
command -v "$PYTHON" >/dev/null || { echo "Python >= 3.10 is required" >&2; exit 1; }
TMP=$(mktemp -d "${TMPDIR:-/tmp}/netbot-bootstrap.XXXXXX")
cleanup() { rm -rf "$TMP"; }
trap cleanup EXIT HUP INT TERM
ARCHIVE="$TMP/netbot-$VERSION.zip"
curl --fail --location --silent --show-error "$URL" --output "$ARCHIVE"
ACTUAL=$(shasum -a 256 "$ARCHIVE" | awk '{print $1}')
[ "$ACTUAL" = "$EXPECTED" ] || { echo "release checksum mismatch" >&2; exit 1; }
EXTRACT="$TMP/extracted"
mkdir "$EXTRACT"
"$PYTHON" - "$ARCHIVE" "$EXTRACT" "netbot-$VERSION" <<'PY'
import pathlib, sys, zipfile
archive, destination, expected = map(pathlib.Path, sys.argv[1:])
root = pathlib.PurePosixPath(expected.name)
with zipfile.ZipFile(archive) as zf:
    for info in zf.infolist():
        name = pathlib.PurePosixPath(info.filename)
        if name.is_absolute() or ".." in name.parts or not (name == root or root in name.parents):
            raise SystemExit("unsafe release archive path")
        mode = info.external_attr >> 16
        if mode and (mode & 0o170000) == 0o120000:
            raise SystemExit("release archive contains a symlink")
        target = destination.joinpath(*name.parts)
        target.parent.mkdir(parents=True, exist_ok=True)
        if info.is_dir(): target.mkdir(parents=True, exist_ok=True)
        else: target.write_bytes(zf.read(info))
PY
cd "$EXTRACT/netbot-$VERSION"
# --no-service is mandatory: scheduling remains an explicit operator action.
exec ./install.sh --no-service
