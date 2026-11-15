"""Download exact release assets and verify pinned SHA-256. No Go SDK required."""
import argparse
import hashlib
import gzip
import json
from pathlib import Path
import urllib.request
import zipfile

ROOT = Path(__file__).resolve().parents[1]
ASSETS = {
    "windows": {
        "url": "https://github.com/SagerNet/sing-box/releases/download/v1.14.0/sing-box-1.14.0-windows-amd64.zip",
        "sha256": "3ffb56267da14e287be48bd10cf7e6505260125bad940b75101fbb4d5d58e5d6",
    },
    "android": {
        "url": "https://github.com/singbox-android/libbox/releases/download/1.14.0/libbox.aar",
        "sha256": "13fbeabcb4622250762afa1b137daaba861a4dc1875643d18621339912f32330",
    },
}
WINDOWS_FILES = {
    "sing-box.exe": "aad0ede010eafa7b277e520464f3a66fde820103d737eff739f40f3cc9451dcc",
    "libcronet.dll": "eee741046f0a3975124bae349aeac237aa306f3cc4de59ff5de070e74dbfdaeb",
}
XRAY_VERSION = "26.3.27"
MIHOMO_VERSION = "1.19.32"
MIHOMO_ASSET = {
    "url": f"https://github.com/MetaCubeX/mihomo/releases/download/v{MIHOMO_VERSION}/mihomo-windows-amd64-compatible-v{MIHOMO_VERSION}.zip",
    "sha256": "974a4d7ad69aed27aa2e8f91d61113573c14dadb14562c63e58effabf59816f0",
    "member": "mihomo-windows-amd64-compatible.exe",
    "binary_sha256": "04f8d7fc2b314771e1ecbf15951d59f0e1cb7914503c88cfb6972ff6a824e314",
    "license_sha256": "3972dc9744f6499f0f9b2dbf76696f2ae7ad8af9b23dde66d6af86c9dfb36986",
}
MIHOMO_ANDROID = [
    ("arm64-v8", "arm64-v8a", "42b1f2be8702484d3ae6238daab392622f54bd0d264966700f1f28f52596e326", "bb9afbd48717f92d59e07da35fb694b83d40d6edb63eb9033c2ee4174137d195"),
    ("amd64", "x86_64", "91c159015e7d8aaff22153b9fd18749a0c7258d6f252ea344ecace975ce17413", "1c5aa8e8a7006e4093560fe48505fd1587de29210879e806822cb1094b334413"),
    ("armv7", "armeabi-v7a", "cbac13a26ab77ce80871a064783a02246a856a20ab7435fe301fa1665e99acf4", "10e85ebad5380e5cdcb4028b6ba40910593bc9c37ce6b50e9f3a21adfca1408d"),
]
XRAY_ASSETS = {
    "windows": [("Xray-windows-64.zip", "d004c39288ce9ada487c6f398c7c545f7d749e44bdfdd59dbc9f865afba4e1ad", "xray.exe", "15c2d007954ac53ba69b80ec91242786b3c0b71d52649165b4ca1d5cc96ef8f1", "")],
    "android": [
        ("Xray-android-arm64-v8a.zip", "57149ffd48b629c07bf76938e73ab2729fde5910091497eab3e93d1c190f4c1b", "xray", "19101a8191d6d606da975f719c8cdb80b8710b87ab17edc00ef74b9e39588714", "arm64-v8a"),
        ("Xray-android-amd64.zip", "bfa1dd4cb3cd94f92af6c718ac6933cc84bd3ddd8343aa1e413162152930bee5", "xray", "26b2ac1e596242847a247df9e932ac480bf6072c5c686517f5a3017320895814", "x86_64"),
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


def install(platform: str):
    info = ASSETS[platform]
    target = ROOT / "assets/core" if platform == "windows" else ROOT / "extensions/sever_vpn/src/flutter/sever_vpn/android/libs"
    target.mkdir(parents=True, exist_ok=True)
    cached = WINDOWS_FILES if platform == "windows" else {"libbox.aar": info["sha256"]}
    if cached_files(target, cached) and (ROOT / "assets/licenses/sing-box-LICENSE").is_file():
        print(f"Cached sing-box 1.14.0 for {platform}, SHA-256 verified")
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
            expected = "sing-box-1.14.0-windows-amd64/sing-box.exe"
            (target / "sing-box.exe").write_bytes(archive.read(expected))
            (target / "libcronet.dll").write_bytes(archive.read("sing-box-1.14.0-windows-amd64/libcronet.dll"))
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
    print(f"Installed sing-box 1.14.0 for {platform}, SHA-256 verified")


def install_xray(platform: str):
    for name, checksum, member, binary_checksum, abi in XRAY_ASSETS[platform]:
        target = ROOT / "assets/core" if platform == "windows" else ROOT / "extensions/sever_vpn/src/flutter/sever_vpn/android/src/main/jniLibs" / abi
        target.mkdir(parents=True, exist_ok=True)
        binary = "xray.exe" if platform == "windows" else "libxray.so"
        if cached_files(target, {binary: binary_checksum}) and (ROOT / "assets/licenses/xray-LICENSE").is_file():
            print(f"Cached Xray {XRAY_VERSION} for {platform} {abi}, SHA-256 verified")
            continue
        request = urllib.request.Request(f"https://github.com/XTLS/Xray-core/releases/download/v{XRAY_VERSION}/{name}",
                                         headers={"User-Agent": "LunarisVPN-build/0.1"})
        path = target / "xray-download.zip"
        digest = hashlib.sha256()
        with urllib.request.urlopen(request, timeout=60) as source, path.open("wb") as output:
            total = 0
            while data := source.read(1024 * 1024):
                total += len(data)
                if total > 200 * 1024 * 1024:
                    raise RuntimeError("Xray archive exceeds the 200 MiB limit")
                digest.update(data)
                output.write(data)
        if digest.hexdigest() != checksum:
            path.unlink()
            raise RuntimeError("Xray release SHA-256 mismatch; nothing was installed")
        with zipfile.ZipFile(path) as archive:
            data = archive.read(member)
            if hashlib.sha256(data).hexdigest() != binary_checksum:
                raise RuntimeError("Xray binary SHA-256 mismatch")
            (target / binary).write_bytes(data)
            notices = ROOT / "assets/licenses"
            notices.mkdir(parents=True, exist_ok=True)
            (notices / "xray-LICENSE").write_bytes(archive.read("LICENSE"))
        path.unlink()
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
    parser.add_argument("--core", choices=["all", "sing-box", "xray", "mihomo"], default="all")
    args = parser.parse_args()
    if args.core in {"all", "sing-box"}:
        install(args.platform)
    if args.core in {"all", "xray"}:
        install_xray(args.platform)
    if args.core in {"all", "mihomo"}:
        install_mihomo() if args.platform == "windows" else install_mihomo_android()
