"""Verify the current Lunaris client release archives against workspace inputs."""
import hashlib
from pathlib import Path
import tomllib
import zipfile

from PIL import Image

ROOT = Path(__file__).resolve().parents[1]
DIST = ROOT / "dist"
VERSION = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]["version"]
PREFIX = f"LunarisClient-{VERSION}"


def verify():
    sums = (DIST / f"SHA256SUMS-{VERSION}.txt").read_text(encoding="ascii").splitlines()
    assert len(sums) == 3, "Expected Windows, Android and source deliverables"
    for line in sums:
        expected, name = line.split("  ", 1)
        assert name.startswith(PREFIX + "-"), name
        with (DIST / name).open("rb") as stream:
            assert hashlib.file_digest(stream, "sha256").hexdigest() == expected, name
        with zipfile.ZipFile(DIST / name) as archive:
            assert archive.testzip() is None, name
        print("SHA-256 and archive CRC verified:", name)

    files = [
        "pyproject.toml", "README.md", "docs/VALIDATION.md", "docs/windows-icon.md",
        "app/ui/app.js", "app/ui/style.css", "app/ui/index.html",
        "app/backend/src/models.rs", "app/backend/src/engine.rs", "app/backend/tests/backend.rs",
        "app/src-tauri/src/lib.rs", "app/src-tauri/src/desktop.rs", "app/src-tauri/Cargo.toml",
        "app/src-tauri/Cargo.lock", "app/backend/Cargo.toml", "app/backend/Cargo.lock",
        "app/src-tauri/tauri.conf.json", "app/src-tauri/tauri.android.conf.json",
        "app/plugins/lunaris-native/Cargo.toml", "app/package.json", "app/package-lock.json",
        "src/assets/icon_windows.svg", "tests/ui_settings.test.cjs", "scripts/verify_release.py",
        "scripts/prepare_tauri.py", "scripts/patch_tauri_android.py", "scripts/run.ps1",
    ]
    with zipfile.ZipFile(DIST / f"{PREFIX}-source.zip") as source:
        for name in files:
            assert source.read(f"LunarisClient-source/{name}") == (ROOT / name).read_bytes(), name
    print("Source archive matches the final implementation, tests, icons and documentation")

    with zipfile.ZipFile(DIST / f"{PREFIX}-windows-x64.zip") as windows:
        assert windows.read("LunarisClient/LunarisClient.exe") == (DIST / f"windows-{VERSION}/LunarisClient.exe").read_bytes()
        for name in ["README.md", "docs/VALIDATION.md", "docs/windows-icon.md"]:
            assert windows.read(f"LunarisClient/{name}") == (ROOT / name).read_bytes(), name
    print("Windows archive matches the final executable and documentation")

    with Image.open(ROOT / "app/src-tauri/icons/icon.ico") as icon:
        for size in icon.ico.sizes():
            frame = icon.ico.getimage(size).convert("RGBA")
            w, h = size
            assert all(frame.getpixel(p)[3] == 0 for p in [(0, 0), (w-1, 0), (0, h-1), (w-1, h-1)]), size
    print("Every ICO resolution has transparent rounded corners")


if __name__ == "__main__":
    verify()
