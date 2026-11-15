"""Reject APK/AAB builds whose executable cores were changed during packaging."""
import argparse
import hashlib
from pathlib import Path
import zipfile

from fetch_core import MIHOMO_ANDROID, XRAY_ASSETS

def verify(package: Path):
    expected = {(abi, "libmihomo.so"): digest for _, abi, _, digest in MIHOMO_ANDROID}
    expected.update({(abi, "libxray.so"): digest for _, _, _, digest, abi in XRAY_ASSETS["android"]})
    checked = set()
    abis = set()
    with zipfile.ZipFile(package) as archive:
        for entry in archive.namelist():
            if "chaquopy" in entry.lower() or "libpython" in entry.lower() or entry.endswith((".py", ".pyc")):
                raise SystemExit(f"Android package contains an obsolete Python runtime: {entry}")
            if entry.lower().endswith((".exe", ".dll")) or entry.startswith("assets/runtime/"):
                raise SystemExit(f"Android package contains a desktop-only file: {entry}")
            parts = Path(entry).parts
            if len(parts) < 3 or parts[-3] != "lib":
                continue
            abi, name = parts[-2:]
            abis.add(abi)
            if name not in {"libmihomo.so", "libxray.so"}:
                continue
            checksum = hashlib.sha256(archive.read(entry)).hexdigest()
            if checksum != expected.get((abi, name)):
                raise SystemExit(f"Packaged {abi}/{name} SHA-256 mismatch: {checksum}; executable was changed")
            checked.add((abi, name))
    if not checked:
        raise SystemExit("Package contains no verified executable cores")
    missing = {key for key in expected if key[0] in abis} - checked
    if missing:
        raise SystemExit(f"Package is missing executable cores: {sorted(missing)}")
    print(f"Verified {len(checked)} packaged executable cores: {package.name}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("package", type=Path)
    verify(parser.parse_args().package)
