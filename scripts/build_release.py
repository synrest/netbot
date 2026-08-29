from __future__ import annotations
import hashlib
import pathlib
import sys
import zipfile

root = pathlib.Path(sys.argv[1]).resolve()
version = sys.argv[2]
archive = root / "dist" / f"netbot-{version}.zip"
archive.parent.mkdir(exist_ok=True)
include = [pathlib.Path("README.md"), pathlib.Path("pyproject.toml"), pathlib.Path("install.sh"),
           pathlib.Path("uninstall.sh"), pathlib.Path("netbot"), pathlib.Path("config/topology.yaml"),
           pathlib.Path("launchd/com.netbot.watch.plist")]
files = []
for item in include:
    source = root / item
    if source.is_dir():
        files.extend(p for p in source.rglob("*") if p.is_file() and "__pycache__" not in p.parts)
    elif source.is_file():
        files.append(source)
with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED) as zf:
    for source in sorted(files, key=lambda p: p.relative_to(root).as_posix()):
        rel = pathlib.Path(f"netbot-{version}") / source.relative_to(root)
        info = zipfile.ZipInfo(rel.as_posix(), (1980, 1, 1, 0, 0, 0))
        info.compress_type = zipfile.ZIP_DEFLATED
        mode = 0o100755 if source.suffix == ".sh" else 0o100644
        info.external_attr = mode << 16
        zf.writestr(info, source.read_bytes())
digest = hashlib.sha256(archive.read_bytes()).hexdigest()
(archive.with_suffix(archive.suffix + ".sha256")).write_text(f"{digest}  {archive.name}\n")
print(archive)
