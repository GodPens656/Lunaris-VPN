"""Stage a build in an ASCII directory (Dart native-assets hooks fail on Cyrillic paths)."""
import argparse
from pathlib import Path
import shutil
import sys

ROOT = Path(__file__).resolve().parents[1]


def stage(output: Path, target: str = "windows"):
    output = output.resolve()
    if not str(output).isascii() or output == ROOT or ROOT in output.parents:
        raise SystemExit("Choose a separate ASCII directory, e.g. C:/build/sever")
    icon = ROOT / "src/assets/icon.png"
    if not icon.is_file():
        raise SystemExit("Add the application icon at src/assets/icon.png before building")
    android_icon = ROOT / "src/assets/icon_android.png"
    if target != "windows" and not android_icon.is_file():
        raise SystemExit("Add the adaptive-safe Android icon at src/assets/icon_android.png before building")
    output.mkdir(parents=True, exist_ok=True)
    shutil.copy2(ROOT / "pyproject.toml", output / "pyproject.toml")
    for name in ["src", "extensions", "scripts", "tests"]:
        shutil.copytree(ROOT / name, output / name, dirs_exist_ok=True,
            ignore=shutil.ignore_patterns("__pycache__", "*.egg-info", ".pytest_cache", "build"))
    # Never include a Windows executable in the Android Python bundle.
    if target == "windows":
        shutil.copytree(ROOT / "assets", output / "src/assets", dirs_exist_ok=True)
        shutil.copytree(ROOT / "assets", output / "assets", dirs_exist_ok=True)
    else:
        executable = output / "src/assets/core/sing-box.exe"
        executable.unlink(missing_ok=True)
        (output / "src/assets/core/libcronet.dll").unlink(missing_ok=True)
        (output / "src/assets/core/xray.exe").unlink(missing_ok=True)
        (output / "src/assets/core/mihomo.exe").unlink(missing_ok=True)
        if (ROOT / "assets/licenses").exists():
            shutil.copytree(ROOT / "assets/licenses", output / "src/assets/licenses", dirs_exist_ok=True)
    # Keep the source icon authoritative even when shared assets contain an icon.
    # Flet prefers icon_android.png on Android; the generic icon remains for Windows.
    shutil.copy2(icon, output / "src/assets/icon.png")
    if target != "windows":
        shutil.copy2(android_icon, output / "src/assets/icon_android.png")
    if target == "windows":
        sys.path.insert(0, str(ROOT / "src"))
        from sever.branding import prepare_windows_icon
        prepare_windows_icon(output / "src/assets", force=True)
    for name in ["README.md", "LICENSE", "THIRD_PARTY.md"]:
        if (ROOT / name).exists():
            shutil.copy2(ROOT / name, output / name)
    print(output)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("output", type=Path)
    parser.add_argument("--target", choices=["windows", "apk", "aab"], default="windows")
    args = parser.parse_args()
    stage(args.output, args.target)
