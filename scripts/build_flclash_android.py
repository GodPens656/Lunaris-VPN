"""Build Lunaris's arm64 Android binding against the pinned FlClash Go core."""
import argparse
import os
from pathlib import Path
import shutil
import subprocess

ROOT = Path(__file__).resolve().parents[1]
FLCLASH_TAG = "v0.9.4"
FLCLASH_COMMIT = "89791d7c11978bf9b580ba71bffcb00506a17659"
MIHOMO_COMMIT = "5b453f80dbcee6b3ecfb0415bcace24a48c88707"
ANDROID = ROOT / "app/plugins/lunaris-native/android"


def revision(repo):
    return subprocess.check_output(["git", "-C", repo, "rev-parse", "HEAD"], text=True).strip()


def build(ndk):
    repo = ROOT / "build/flclash-upstream-094"
    if not (repo / ".git").exists():
        repo.parent.mkdir(parents=True, exist_ok=True)
        subprocess.run([
            "git", "-c", "core.longpaths=true", "clone", "--depth", "1", "--branch",
            FLCLASH_TAG, "https://github.com/chen08209/FlClash.git", repo,
        ], check=True)
    if revision(repo) != FLCLASH_COMMIT:
        raise SystemExit("FlClash checkout does not match the pinned release")
    core = repo / "core"
    subprocess.run([
        "git", "-C", repo, "-c",
        "submodule.core/Clash.Meta.url=https://github.com/chen08209/Clash.Meta.git",
        "submodule", "update", "--init", "--depth", "1", "core/Clash.Meta",
    ], check=True)
    if revision(core / "Clash.Meta") != MIHOMO_COMMIT:
        raise SystemExit("Mihomo submodule does not match the pinned FlClash release")
    for source in (repo, core / "Clash.Meta"):
        if subprocess.check_output(["git", "-C", source, "status", "--porcelain", "-uno"], text=True).strip():
            raise SystemExit(f"Pinned FlClash source has tracked modifications: {source}")
    bridge = core / "cmd/lunaris-android"
    bridge.mkdir(parents=True, exist_ok=True)
    for name in ["bridge.go", "bridge.c", "bridge.h"]:
        shutil.copyfile(ANDROID / "src/main/go/flclash" / name, bridge / name)

    clang_name = "clang.exe" if os.name == "nt" else "clang"
    compilers = sorted(ndk.glob(f"toolchains/llvm/prebuilt/*/bin/{clang_name}"))
    if len(compilers) != 1:
        raise SystemExit(f"Expected one Clang installation under the Android NDK: {ndk}")
    clang = compilers[0]
    env = dict(os.environ, GOOS="android", GOARCH="arm64", CGO_ENABLED="1",
               CC=f'"{clang}" --target=aarch64-linux-android26')
    result = ROOT / "build/flclash-android/liblunaris_mihomo.so"
    result.parent.mkdir(parents=True, exist_ok=True)
    subprocess.run([
        "go", "build", "-mod=readonly", "-trimpath", "-buildvcs=false", "-buildmode=c-shared",
        "-tags=with_gvisor", "-ldflags=-s -w -X github.com/metacubex/mihomo/constant.Version=1.19.34",
        "-o", result, "./cmd/lunaris-android",
    ], cwd=core, env=env, check=True)
    package = ANDROID / "src/main/jniLibs/arm64-v8a/liblunaris_mihomo.so"
    package.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(result, package)
    print(f"Built FlClash {FLCLASH_TAG} Android arm64 core: {package}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--ndk", type=Path, required=True)
    build(parser.parse_args().ndk.resolve())
