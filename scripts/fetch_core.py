"""Download exact release assets and verify pinned SHA-256. No Go SDK required."""
import argparse
import hashlib
import gzip
import json
from pathlib import Path
import tempfile
import urllib.request
import zipfile

ROOT = Path(__file__).resolve().parents[1]
SING_BOX_VERSION = "1.14.4"
SING_BOX_WINDOWS = f"sing-box-{SING_BOX_VERSION}-windows-amd64"
ASSETS = {
    "windows": {
        "url": f"https://github.com/SagerNet/sing-box/releases/download/v{SING_BOX_VERSION}/{SING_BOX_WINDOWS}.zip",
        "sha256": "99185d75d314a07dbba4a130c8ad986cbeb629a07927975636b341ca61f991df",
    },
    "android": {
        "url": f"https://github.com/singbox-android/libbox/releases/download/{SING_BOX_VERSION}/libbox.aar",
        "sha256": "d2685924a657705beda44e94c6dc499e781df1ad20d65474e3591ec2f8b96465",
    },
}
WINDOWS_FILES = {
    "sing-box.exe": "8f30682ee198855440d2a7fe070d5d3653793b2d01bb8c85eea88f93bbe7c8b9",
    "libcronet.dll": "3217c6260fbca5f16072e0b79735742f40109a63bb0ff88fd6b96dd6b54a2928",
}
XRAY_VERSION = "26.11.9"
MIHOMO_VERSION = "1.19.34"
FLCLASH_VERSION = "0.9.4"
FLCLASH_WINDOWS_ARCHIVE = f"FlClash-{FLCLASH_VERSION}-windows-amd64-portable.zip"
FLCLASH_WINDOWS_SHA256 = "8fab8ab4edead33a6c6d4f249fd90a287acbf66a99cc5bd207fcfc034f3b1224"
FLCLASH_CORE_SHA256 = "866ee89af2ea5c47f228dc3f2f5b876439270d2997928b9b5cfcb560d109b36f"
WINTUN_SHA256 = "e5da8447dc2c320edc0fc52fa01885c103de8c118481f683643cacc3220dafce"
WINTUN_LICENSE_SHA256 = "183adac21e7d96c508c8fd34d394b7b6708bc81564ad1bad61ab66143a008cd2"
MIHOMO_ASSET = {
    "url": f"https://github.com/MetaCubeX/mihomo/releases/download/v{MIHOMO_VERSION}/mihomo-windows-amd64-compatible-v{MIHOMO_VERSION}.zip",
    "sha256": "cd6738d4648cc1a5f48049a1343b697ab510889d648f045c5c780fc1ab443a79",
    "member": "mihomo-windows-amd64-compatible.exe",
    "binary_sha256": "5a0231811a80b27477ebdee15684b41946d01afbd2114534e9a4b256125ca147",
    "license_sha256": "3972dc9744f6499f0f9b2dbf76696f2ae7ad8af9b23dde66d6af86c9dfb36986",
}
MIHOMO_ANDROID = [
    ("arm64-v8", "arm64-v8a", "48a71fc6a68e2909587176e0ab7185d8f2fac298fa96ccdacf30ea86ab2359b5", "1369bebba2b7a6fe971fe6ece0cb5aa18c81e49c89dd8340f43e5e7583d3da36"),
    ("amd64", "x86_64", "99ce9a0226e12c718e749436d7ae0f35300b6e19f757edd09994efd1eab5d2ff", "070332fedbc1268df6f1d6f329a072b14b1ba8b102cd45465c3681bd12682fed"),
    ("armv7", "armeabi-v7a", "a4959825f5af98f5a60c7b6ab0d23e766d647d17795315e3ac57b5b5bed918e7", "5047466f174206ef718a505f09652ca8f17c1f126c4a60639dc1208be990c58d"),
]
XRAY_ASSETS = {
    "windows": [("Xray-windows-64.zip", "1262522266337b824f07beb8e1375786b437683b3890105469088f8e17e0a69d", "xray.exe", "1ca7a2cf61ba2c5d20b21a80d405b57933939751081cb289f07bd8ddf7cc3185", "")],
    "android": [
        ("Xray-android-arm64-v8a.zip", "edcefc25b9b3195b11e18624c8269a969d6aabc39c6298a9a5ab29de15d46f3b", "xray", "dbfe83c136ebb58635f5ad4e21d1df077473aa6fc4bfa1b7ee193516d0af8255", "arm64-v8a"),
        ("Xray-android-amd64.zip", "48c266cdb9660dade968814e2f91d84e6aff534b7c3762ca3e385fb8aa475bd8", "xray", "63ba44d391e1bfd4061fad9584ed171671b5928b91128001bf4921e8cb9b46aa", "x86_64"),
    ],
}


def cached_files(target, expected):
    for name, checksum in expected.items():
        path = target / name
        if not path.is_file():
            return False
        with path.open("rb") as source:
            if hashlib.file_digest(source, "sha256").hexdigest() != checksum:
                return False
    return True


def download_verified(url, target, checksum):
    request = urllib.request.Request(url, headers={"User-Agent": "LunarisVPN-build/0.1"})
    target.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(dir=target.parent, delete=False) as output:
        temporary = Path(output.name)
        try:
            with urllib.request.urlopen(request, timeout=60) as source:
                digest = hashlib.sha256()
                total = 0
                while chunk := source.read(1024 * 1024):
                    total += len(chunk)
                    if total > 200 * 1024 * 1024:
                        raise RuntimeError("Release asset exceeds the 200 MiB limit")
                    digest.update(chunk)
                    output.write(chunk)
            if digest.hexdigest() != checksum:
                raise RuntimeError(f"SHA-256 mismatch for {target.name}")
            output.close()
            temporary.replace(target)
        finally:
            output.close()
            temporary.unlink(missing_ok=True)


def install_flclash_windows():
    destination = ROOT / "assets/core"
    if cached_files(destination, {"FlClashCore.exe": FLCLASH_CORE_SHA256}):
        print(f"Cached FlClashCore {FLCLASH_VERSION} for Windows, SHA-256 verified")
        return
    cache = ROOT / "build/core-downloads"
    artifact = cache / FLCLASH_WINDOWS_ARCHIVE
    if not cached_files(cache, {artifact.name: FLCLASH_WINDOWS_SHA256}):
        url = f"https://github.com/chen08209/FlClash/releases/download/v{FLCLASH_VERSION}/{artifact.name}"
        download_verified(url, artifact, FLCLASH_WINDOWS_SHA256)
    destination.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(artifact) as archive:
        member, = [name for name in archive.namelist() if Path(name).name == "FlClashCore.exe"]
        manifest_path = str(Path(member).with_name("manifest.json").as_posix())
        manifest = json.loads(archive.read(manifest_path))
        binary = archive.read(member)
        if hashlib.sha256(binary).hexdigest() != FLCLASH_CORE_SHA256 or manifest["coreSha256"] != FLCLASH_CORE_SHA256:
            raise RuntimeError("FlClashCore executable does not match the release manifest")
        temporary = destination / "FlClashCore.exe.download"
        try:
            temporary.write_bytes(binary)
            temporary.replace(destination / "FlClashCore.exe")
        finally:
            temporary.unlink(missing_ok=True)
    print(f"Installed FlClashCore {FLCLASH_VERSION} for Windows, SHA-256 verified")


def install(platform: str):
    info = ASSETS[platform]
    target = ROOT / "assets/core" if platform == "windows" else ROOT / "extensions/sever_vpn/src/flutter/sever_vpn/android/libs"
    target.mkdir(parents=True, exist_ok=True)
    cached = WINDOWS_FILES if platform == "windows" else {"libbox.aar": info["sha256"]}
    if cached_files(target, cached) and (ROOT / "assets/licenses/sing-box-LICENSE").is_file():
        print(f"Cached sing-box {SING_BOX_VERSION} for {platform}, SHA-256 verified")
        return
    path = target / ("core-download.zip" if platform == "windows" else "libbox.aar.download")
    request = urllib.request.Request(info["url"], headers={"User-Agent": "LunarisVPN-build/0.1"})
    digest = hashlib.sha256()
    with urllib.request.urlopen(request, timeout=60) as source, path.open("wb") as output:
        total = 0
        while data := source.read(1024 * 1024):
            total += len(data)
            if total > 200 * 1024 * 1024:
                raise RuntimeError("Release asset is larger than the allowed 200 MiB")
            digest.update(data)
            output.write(data)
    if digest.hexdigest() != info["sha256"]:
        path.unlink()
        raise RuntimeError("Release asset SHA-256 mismatch; nothing was installed")
    if platform == "windows":
        with zipfile.ZipFile(path) as archive:
            for name in WINDOWS_FILES:
                (target / name).write_bytes(archive.read(f"{SING_BOX_WINDOWS}/{name}"))
            notices = ROOT / "assets/licenses"
            notices.mkdir(parents=True, exist_ok=True)
            for name in archive.namelist():
                if Path(name).name in {"LICENSE", "LICENSE.txt"}:
                    (notices / "sing-box-LICENSE").write_bytes(archive.read(name))
        path.unlink()
    else:
        with zipfile.ZipFile(path) as archive:
            required = {"jni/arm64-v8a/libbox.so", "classes.jar"}
            if not required.issubset(archive.namelist()):
                raise RuntimeError("AAR does not contain the required ABI or Java API")
        path.replace(target / "libbox.aar")
    print(f"Installed sing-box {SING_BOX_VERSION} for {platform}, SHA-256 verified")


def install_xray(platform: str):
    for name, checksum, member, binary_checksum, abi in XRAY_ASSETS[platform]:
        target = ROOT / "assets/core" if platform == "windows" else ROOT / "extensions/sever_vpn/src/flutter/sever_vpn/android/src/main/jniLibs" / abi
        target.mkdir(parents=True, exist_ok=True)
        binary = "xray.exe" if platform == "windows" else "libxray.so"
        notices = ROOT / "assets/licenses"
        files = {binary: binary_checksum}
        if platform == "windows":
            files["wintun.dll"] = WINTUN_SHA256
        if (cached_files(target, files) and (notices / "xray-LICENSE").is_file()
                and (platform != "windows" or cached_files(notices, {"wintun-LICENSE": WINTUN_LICENSE_SHA256}))):
            print(f"Cached Xray {XRAY_VERSION} for {platform} {abi}, SHA-256 verified")
            continue
        cache = ROOT / "build/core-downloads"
        path = cache / name
        if not cached_files(cache, {name: checksum}):
            url = f"https://github.com/XTLS/Xray-core/releases/download/v{XRAY_VERSION}/{name}"
            download_verified(url, path, checksum)
        with zipfile.ZipFile(path) as archive:
            data = archive.read(member)
            if hashlib.sha256(data).hexdigest() != binary_checksum:
                raise RuntimeError("Xray binary SHA-256 mismatch")
            if platform == "windows":
                wintun = archive.read("wintun.dll")
                license_data = archive.read("LICENSE-Wintun")
                if (hashlib.sha256(wintun).hexdigest() != WINTUN_SHA256
                        or hashlib.sha256(license_data).hexdigest() != WINTUN_LICENSE_SHA256):
                    raise RuntimeError("Wintun binary or license SHA-256 mismatch")
                notices.mkdir(parents=True, exist_ok=True)
                (target / "wintun.dll").write_bytes(wintun)
                (notices / "wintun-LICENSE").write_bytes(license_data)
            (target / binary).write_bytes(data)
            notices.mkdir(parents=True, exist_ok=True)
            (notices / "xray-LICENSE").write_bytes(archive.read("LICENSE"))
        print(f"Installed Xray {XRAY_VERSION} for {platform} {abi}, SHA-256 verified")


def mihomo_license() -> bytes:
    path = ROOT / "assets/licenses/mihomo-LICENSE"
    if cached_files(path.parent, {path.name: MIHOMO_ASSET["license_sha256"]}):
        return path.read_bytes()
    request = urllib.request.Request(f"https://raw.githubusercontent.com/MetaCubeX/mihomo/v{MIHOMO_VERSION}/LICENSE",
                                     headers={"User-Agent": "LunarisVPN-build/0.1"})
    with urllib.request.urlopen(request, timeout=30) as source:
        data = source.read(1024 * 1024)
    if hashlib.sha256(data).hexdigest() != MIHOMO_ASSET["license_sha256"]:
        raise RuntimeError("Mihomo license SHA-256 mismatch; nothing was installed")
    return data


def install_mihomo_android():
    notices = ROOT / "assets/licenses"
    license_data = mihomo_license()
    notices.mkdir(parents=True, exist_ok=True)
    (notices / "mihomo-LICENSE").write_bytes(license_data)
    for arch, abi, checksum, binary_checksum in MIHOMO_ANDROID:
        target = ROOT / "extensions/sever_vpn/src/flutter/sever_vpn/android/src/main/jniLibs" / abi
        target.mkdir(parents=True, exist_ok=True)
        if cached_files(target, {"libmihomo.so": binary_checksum}):
            print(f"Cached Mihomo {MIHOMO_VERSION} for android {abi}, SHA-256 verified")
            continue
        path = target / "mihomo-download.gz"
        try:
            url = f"https://github.com/MetaCubeX/mihomo/releases/download/v{MIHOMO_VERSION}/mihomo-android-{arch}-v{MIHOMO_VERSION}.gz"
            request = urllib.request.Request(url, headers={"User-Agent": "LunarisVPN-build/0.1"})
            digest = hashlib.sha256()
            with urllib.request.urlopen(request, timeout=60) as source, path.open("wb") as output:
                total = 0
                while data := source.read(1024 * 1024):
                    total += len(data)
                    if total > 200 * 1024 * 1024:
                        raise RuntimeError("Mihomo archive exceeds the 200 MiB limit")
                    digest.update(data)
                    output.write(data)
            if digest.hexdigest() != checksum:
                raise RuntimeError("Mihomo release SHA-256 mismatch; nothing was installed")
            with gzip.open(path, "rb") as source:
                binary = source.read(200 * 1024 * 1024 + 1)
            if hashlib.sha256(binary).hexdigest() != binary_checksum:
                raise RuntimeError("Mihomo binary SHA-256 mismatch; nothing was installed")
            temporary = target / "libmihomo.so.download"
            temporary.write_bytes(binary)
            temporary.replace(target / "libmihomo.so")
        finally:
            path.unlink(missing_ok=True)
        print(f"Installed Mihomo {MIHOMO_VERSION} for android {abi}, SHA-256 verified")


def install_mihomo():
    target = ROOT / "assets/core"
    notices = ROOT / "assets/licenses"
    target.mkdir(parents=True, exist_ok=True)
    notices.mkdir(parents=True, exist_ok=True)
    if cached_files(target, {"mihomo.exe": MIHOMO_ASSET["binary_sha256"]}) and cached_files(notices, {"mihomo-LICENSE": MIHOMO_ASSET["license_sha256"]}):
        print(f"Cached Mihomo {MIHOMO_VERSION} for windows, SHA-256 verified")
        return
    path = target / "mihomo-download.zip"
    try:
        request = urllib.request.Request(MIHOMO_ASSET["url"], headers={"User-Agent": "LunarisVPN-build/0.1"})
        digest = hashlib.sha256()
        with urllib.request.urlopen(request, timeout=60) as source, path.open("wb") as output:
            total = 0
            while data := source.read(1024 * 1024):
                total += len(data)
                if total > 200 * 1024 * 1024:
                    raise RuntimeError("Mihomo archive exceeds the 200 MiB limit")
                digest.update(data)
                output.write(data)
        if digest.hexdigest() != MIHOMO_ASSET["sha256"]:
            raise RuntimeError("Mihomo release SHA-256 mismatch; nothing was installed")
        with zipfile.ZipFile(path) as archive:
            binary = archive.read(MIHOMO_ASSET["member"])
        if hashlib.sha256(binary).hexdigest() != MIHOMO_ASSET["binary_sha256"]:
            raise RuntimeError("Mihomo binary SHA-256 mismatch; nothing was installed")
        license_data = mihomo_license()
        (notices / "mihomo-LICENSE").write_bytes(license_data)
        temporary = target / "mihomo.exe.download"
        temporary.write_bytes(binary)
        temporary.replace(target / "mihomo.exe")
    finally:
        path.unlink(missing_ok=True)
    print(f"Installed Mihomo {MIHOMO_VERSION} for windows, SHA-256 verified")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("platform", choices=list(ASSETS))
    parser.add_argument("--core", choices=["all", "sing-box", "xray", "mihomo", "flclash"], default="all")
    args = parser.parse_args()
    if args.core in {"all", "sing-box"}:
        install(args.platform)
    if args.core in {"all", "xray"}:
        install_xray(args.platform)
    if args.core in {"all", "mihomo"}:
        install_mihomo() if args.platform == "windows" else install_mihomo_android()
    if args.core == "flclash":
        if args.platform != "windows":
            parser.error("FlClashCore executable is a Windows build input")
        install_flclash_windows()
