"""Apply repeatable VPN settings after `tauri android init`."""
from pathlib import Path
import json
import re
import shutil
import sys
import xml.etree.ElementTree as ET
from PIL import Image


def patch(root):
    android = root / "app/src-tauri/gen/android"
    # Existing generated projects retain the old launcher label after a rename.
    product = json.loads((root / "app/src-tauri/tauri.conf.json").read_text(encoding="utf-8"))["productName"]
    strings = android / "app/src/main/res/values/strings.xml"
    labels = ET.parse(strings)
    for label in labels.getroot().findall("string"):
        if label.get("name") in {"app_name", "main_activity_title"}:
            label.text = product
    labels.write(strings, encoding="utf-8", xml_declaration=True)
    obsolete = (android / "app/src/main/assets/runtime").resolve()
    if obsolete.is_dir():
        assert obsolete.is_relative_to(android.resolve())
        shutil.rmtree(obsolete)
    root_gradle = android / "build.gradle.kts"
    root_code = root_gradle.read_text(encoding="utf-8")
    root_code = re.sub(r'org.jetbrains.kotlin:kotlin-gradle-plugin:[^"\s]+',
                       'org.jetbrains.kotlin:kotlin-gradle-plugin:2.1.0', root_code)
    root_gradle.write_text(root_code, encoding="utf-8")
    gradle = android / "app/build.gradle.kts"
    content = gradle.read_text(encoding="utf-8").replace("**/libmihomo.so", "**/liblunaris_mihomo.so")
    if not re.search(r"// Lunaris (?:VPN|client) packaging", content):
        content += '''
// Lunaris client packaging: preserve executable Go ELF files byte-for-byte.
android {
    defaultConfig { ndk { abiFilters += listOf("arm64-v8a") } }
    packaging {
        jniLibs {
            useLegacyPackaging = true
            keepDebugSymbols += setOf("**/libxray.so", "**/liblunaris_mihomo.so")
        }
    }
    buildTypes.getByName("release") {
        signingConfig = signingConfigs.getByName("debug")
    }
}
'''
    gradle.write_text(content, encoding="utf-8")
    manifest = android / "app/src/main/AndroidManifest.xml"
    content = manifest.read_text(encoding="utf-8")
    if 'android:scheme="lunaris"' not in content:
        content = content.replace("        </activity>", '''            <intent-filter>
                <action android:name="android.intent.action.VIEW" />
                <category android:name="android.intent.category.DEFAULT" />
                <category android:name="android.intent.category.BROWSABLE" />
                <data android:scheme="lunaris" />
            </intent-filter>
        </activity>''', 1)
    manifest.write_text(content, encoding="utf-8")
    # A direct `node tauri.js android init` records an unusable callback. Always
    # route Gradle through the package script, independent of the initializer.
    for task in (android / "buildSrc/src").rglob("BuildTask.kt"):
        code = task.read_text(encoding="utf-8")
        code = re.sub(r'val executable = .*;', 'val executable = "npm";', code, count=1)
        code = re.sub(r'val args = listOf\(.*\);', 'val args = listOf("run", "tauri", "--", "android", "android-studio-script");', code, count=1)
        task.write_text(code, encoding="utf-8")
    with Image.open(root / "src/assets/icon_android.png") as source:
        res = android / "app/src/main/res"
        for density, size in [("mdpi",48),("hdpi",72),("xhdpi",96),("xxhdpi",144),("xxxhdpi",192)]:
            folder = res / f"mipmap-{density}"
            folder.mkdir(parents=True, exist_ok=True)
            for name in ["ic_launcher.png", "ic_launcher_round.png", "ic_launcher_foreground.png"]:
                source.resize((size, size), Image.Resampling.LANCZOS).save(folder / name)
    print("Configured VPN packaging, deep links and development signing")


if __name__ == "__main__":
    patch(Path(sys.argv[1]).resolve() if len(sys.argv) > 1 else Path(__file__).resolve().parents[1])
