"""Reject APK/AAB builds whose executable cores were changed during packaging."""
import argparse
import hashlib
from pathlib import Path
import zipfile

from fetch_core import ROOT, XRAY_ASSETS

FLCLASH_CORE = ROOT / "app/plugins/lunaris-native/android/src/main/jniLibs/arm64-v8a/liblunaris_mihomo.so"

def verify(package: Path):
    with FLCLASH_CORE.open("rb") as source:
        core_digest = hashlib.file_digest(source, "sha256").hexdigest()
    expected = {("arm64-v8a", FLCLASH_CORE.name): core_digest}
    expected.update({(abi, "libxray.so"): digest for _, _, _, digest, abi in XRAY_ASSETS["android"]
                     if abi == "arm64-v8a"})
    checked = set()
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
            if name == "libmihomo.so":
                raise SystemExit("Package includes the legacy standalone Mihomo executable")
            if name not in {FLCLASH_CORE.name, "libxray.so"}:
                continue
            checksum = hashlib.sha256(archive.read(entry)).hexdigest()
            if checksum != expected.get((abi, name)):
                raise SystemExit(f"Packaged {abi}/{name} SHA-256 mismatch: {checksum}; executable was changed")
            checked.add((abi, name))
    if not checked:
        raise SystemExit("Package contains no verified executable cores")
    missing = set(expected) - checked
    if missing:
        raise SystemExit(f"Package is missing executable cores: {sorted(missing)}")
    print(f"Verified {len(checked)} packaged executable cores: {package.name}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("package", type=Path)
    verify(parser.parse_args().package)
