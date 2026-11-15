"""Archive an already built Windows folder and project source; write SHA256SUMS."""
import argparse
import hashlib
from pathlib import Path
import tomllib
import zipfile

ROOT = Path(__file__).resolve().parents[1]
DIST = ROOT / "dist"
VERSION = tomllib.loads(ROOT.joinpath("pyproject.toml").read_text(encoding="utf-8"))["project"]["version"]


def package(windows: Path = DIST / "windows"):
    if not windows.joinpath("LunarisClient.exe").is_file():
        raise SystemExit("Copy the Tauri executable and runtime to the release directory first")
    for path in windows.rglob("*"):
        if path.is_file() and ("python" in path.name.lower() or path.suffix in {".py", ".pyc"} or path.name == "lunaris-engine.exe"):
            raise SystemExit(f"Release contains an obsolete Python backend: {path}")
    for name in ["README.md", "LICENSE", "THIRD_PARTY.md"]:
        windows.joinpath(name).write_bytes(ROOT.joinpath(name).read_bytes())
    with zipfile.ZipFile(DIST / f"LunarisClient-{VERSION}-windows-x64.zip", "w", zipfile.ZIP_DEFLATED, compresslevel=6) as archive:
        for path in sorted(windows.rglob("*")):
            if path.is_file():
                archive.write(path, Path("LunarisClient") / path.relative_to(windows))
        for path in ROOT.joinpath("docs").glob("*"):
            if path.is_file():
                archive.write(path, Path("LunarisClient/docs") / path.name)
    with zipfile.ZipFile(DIST / f"LunarisClient-{VERSION}-source.zip", "w", zipfile.ZIP_DEFLATED, compresslevel=6) as archive:
        for folder in ["app", "src", "extensions", "scripts", "tests", "docs", ".github", "assets/licenses"]:
            for path in sorted(ROOT.joinpath(folder).rglob("*")):
                excluded = {"__pycache__", "node_modules", "target", "gen", ".gradle", "build", "python", "jniLibs"}
                if path.is_file() and not excluded.intersection(path.relative_to(ROOT).parts) and "assets/core" not in path.as_posix() and path.suffix not in {".pyc", ".aar", ".exe", ".dll", ".so"}:
                    archive.write(path, Path("LunarisClient-source") / path.relative_to(ROOT))
        for name in ["README.md", "LICENSE", "THIRD_PARTY.md", "pyproject.toml", ".gitignore"]:
            archive.write(ROOT / name, f"LunarisClient-source/{name}")
    sums = []
    for path in sorted(DIST.iterdir()):
        if path.is_file() and path.suffix in {".zip", ".apk", ".aab"}:
            with path.open("rb") as stream:
                digest = hashlib.file_digest(stream, "sha256").hexdigest()
            sums.append(f"{digest}  {path.name}")
    DIST.joinpath("SHA256SUMS.txt").write_text("\n".join(sums) + "\n", encoding="ascii")
    release_sums = [line for line in sums if line.split("  ", 1)[1].startswith(f"LunarisClient-{VERSION}-")]
    DIST.joinpath(f"SHA256SUMS-{VERSION}.txt").write_text("\n".join(release_sums) + "\n", encoding="ascii")
    print("Release archives and SHA256SUMS.txt created in dist")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--windows-dir", type=Path, default=DIST / "windows")
    package(parser.parse_args().windows_dir)
