"""Stage shared native code and offline UI assets for the Tauri build."""
from pathlib import Path
import shutil
import subprocess

ROOT = Path(__file__).resolve().parents[1]


def prepare():
    icons = ROOT / "app/src-tauri/icons"
    icons.mkdir(parents=True, exist_ok=True)
    # Render the desktop tile's vector clipping path with Tauri's native icon
    # exporter. Every ICO/PNG resolution retains the transparent rounded edge.
    subprocess.run(["node", str(ROOT / "app/node_modules/@tauri-apps/cli/tauri.js"),
        "icon", str(ROOT / "src/assets/icon_windows.svg"), "--output", str(icons)], check=True)
    shutil.copy2(icons / "128x128@2x.png", ROOT / "app/ui/icon.png")
    shutil.copytree(ROOT / "src/sever/flag_assets", ROOT / "app/ui/flags", dirs_exist_ok=True)

    native = ROOT / "app/plugins/lunaris-native/android"
    legacy = ROOT / "extensions/sever_vpn/src/flutter/sever_vpn/android"
    # The Android Tauri service and manifest are maintained in the plugin.
    # Stage only the prebuilt assets shared with the legacy Android build.
    for relative in ("libs/libbox.aar", "src/main/jniLibs/arm64-v8a/libxray.so"):
        source = legacy / relative
        if source.is_file():
            target = native / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, target)
    (native / "src/main/jniLibs/arm64-v8a/libmihomo.so").unlink(missing_ok=True)
    # Runtime contains only the verified VPN cores. Application code is linked
    # into Tauri from app/backend on both platforms.
    runtime = ROOT / "build/tauri-runtime-rust/assets"
    shutil.copytree(ROOT / "assets/core", runtime / "core", dirs_exist_ok=True)
    shutil.copytree(ROOT / "assets/licenses", runtime / "licenses", dirs_exist_ok=True)
    print("Prepared Tauri icons, flags, Rust runtime assets and VPN-service sources")


if __name__ == "__main__":
    prepare()
