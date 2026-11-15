"""Copy build inputs to a dedicated ASCII directory, preserving build caches."""
import argparse
from pathlib import Path
import shutil

ROOT = Path(__file__).resolve().parents[1]


def stage(output):
    output = output.resolve()
    if not str(output).isascii() or output == ROOT or ROOT in output.parents:
        raise SystemExit("Choose a separate ASCII staging directory")
    output.mkdir(parents=True, exist_ok=True)
    for folder in ["app", "src", "scripts"]:
        shutil.copytree(ROOT / folder, output / folder, dirs_exist_ok=True,
            ignore=shutil.ignore_patterns("__pycache__", "target", ".gradle", "gen", "build", "python", "*.pyc"))
    runtime = ROOT / "build/tauri-runtime-rust"
    if runtime.exists():
        shutil.copytree(runtime, output / "build/tauri-runtime-rust", dirs_exist_ok=True)
    for name in ["pyproject.toml", "README.md", "LICENSE", "THIRD_PARTY.md"]:
        shutil.copy2(ROOT / name, output / name)
    print(output)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("output", type=Path)
    stage(parser.parse_args().output)
