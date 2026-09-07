from __future__ import annotations
import hashlib
import pathlib
import sys
import zipfile

root = pathlib.Path(sys.argv[1]).resolve()
version = sys.argv[2]
archive = root / "dist" / f"netbot-{version}.zip"
archive.parent.mkdir(exist_ok=True)
include = [pathlib.Path("README.md"), pathlib.Path("pyproject.toml"), pathlib.Path("install.sh"), pathlib.Path("bootstrap.sh"),
           pathlib.Path("uninstall.sh"), pathlib.Path("netbot"),
           pathlib.Path("launchd/com.netbot.watch.plist"), pathlib.Path("systemd/netbot-watch.service"),
           pathlib.Path("openrc/netbot-watch")]
files = []
for item in include:
    source = root / item
    if source.is_dir():
        files.extend((p, p.relative_to(root)) for p in source.rglob("*") if p.is_file() and "__pycache__" not in p.parts)
    elif source.is_file():
        files.append((source, item))
files.append((root / "config/topology.example.yaml", pathlib.Path("config/topology.yaml")))
with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED) as zf:
    for source, relative in sorted(files, key=lambda pair: pair[1].as_posix()):
        rel = pathlib.Path(f"netbot-{version}") / relative
        info = zipfile.ZipInfo(rel.as_posix(), (1980, 1, 1, 0, 0, 0))
        info.compress_type = zipfile.ZIP_DEFLATED
        mode = 0o100755 if source.suffix == ".sh" or source.parent.name == "openrc" else 0o100644
        info.external_attr = mode << 16
        zf.writestr(info, source.read_bytes())
digest = hashlib.sha256(archive.read_bytes()).hexdigest()
(archive.with_suffix(archive.suffix + ".sha256")).write_text(f"{digest}  {archive.name}\n")
print(archive)
