"""Launch the Tauri application."""
from pathlib import Path
import shutil
import subprocess


def run():
    root = Path(__file__).resolve().parents[2]
    packaged = root / "dist/windows-0.6.1/LunarisVPN.exe"
    if packaged.is_file():
        subprocess.Popen([str(packaged)], cwd=packaged.parent)
        return
    node = shutil.which("node")
    cli = root / "app/node_modules/@tauri-apps/cli/tauri.js"
    if not node or not cli.is_file():
        raise SystemExit("Install Rust and run npm ci in app, then scripts/run.ps1. See README.md.")
    subprocess.run([node, str(cli), "dev"], cwd=root / "app", check=True)
