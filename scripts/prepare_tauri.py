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
    kotlin = native / "src/main/java/dev/sever/vpn"
    for source in (legacy / "src/main/kotlin/dev/sever/vpn").glob("*.kt"):
        if source.name != "SeverVpnPlugin.kt":
            shutil.copy2(source, kotlin / source.name)
    shutil.copytree(legacy / "src/main/res", native / "src/main/res", dirs_exist_ok=True)
    manifest = (legacy / "src/main/AndroidManifest.xml").read_text(encoding="utf-8")
    manifest = manifest.replace("        <service", '        <activity android:name="dev.sever.vpn.VpnPermissionActivity" android:exported="false" android:theme="@android:style/Theme.Material.Light.NoActionBar" />\n        <service', 1)
    (native / "src/main/AndroidManifest.xml").write_text(manifest, encoding="utf-8")
    for name in ["libs", "src/main/jniLibs"]:
        shutil.copytree(legacy / name, native / name, dirs_exist_ok=True)
    # Runtime contains only the verified VPN cores. Application code is linked
    # into Tauri from app/backend on both platforms.
    runtime = ROOT / "build/tauri-runtime-rust/assets"
    shutil.copytree(ROOT / "assets/core", runtime / "core", dirs_exist_ok=True)
    shutil.copytree(ROOT / "assets/licenses", runtime / "licenses", dirs_exist_ok=True)
    print("Prepared Tauri icons, flags, Rust runtime assets and VPN-service sources")


if __name__ == "__main__":
    prepare()
