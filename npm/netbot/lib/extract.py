import os
import pathlib
import sys
import zipfile

archive, destination, expected_root = map(pathlib.Path, sys.argv[1:])
destination.mkdir(parents=True, exist_ok=True)
with zipfile.ZipFile(archive) as archive_file:
    members = archive_file.infolist()
    root = pathlib.PurePosixPath(expected_root.name)
    for member in members:
        name = pathlib.PurePosixPath(member.filename)
        if name.is_absolute() or ".." in name.parts:
            raise SystemExit("release archive contains path traversal")
        if not (name == root or root in name.parents):
            raise SystemExit("release archive contains unexpected top-level entry")
        mode = member.external_attr >> 16
        if mode and (mode & 0o170000) == 0o120000:
            raise SystemExit("release archive contains a symlink")
        target = destination.joinpath(*name.parts)
        if not pathlib.Path(os.path.commonpath((destination.resolve(), target.resolve()))) == destination.resolve():
            raise SystemExit("release archive escapes staging directory")
        target.parent.mkdir(parents=True, exist_ok=True)
        if member.is_dir():
            target.mkdir(parents=True, exist_ok=True)
        else:
            target.write_bytes(archive_file.read(member))
