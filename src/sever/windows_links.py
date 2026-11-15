"""Per-user URL registration and a DPAPI-protected inbox for the running client.

The small launcher starts Flet without arguments: its Windows bootstrap treats
arguments as a development server URL, before embedded Python can process them.
"""
from pathlib import Path
import os
import subprocess
import sys
import time

from .storage import atomic_write, dpapi
from .models import UserError


def register_protocol(directory: Path) -> None:
    import winreg

    def literal(value):
        return "'" + str(value).replace("'", "''") + "'"

    executable = Path(os.environ.get("LUNARIS_LAUNCHER", sys.executable))
    source = Path(__file__).resolve().parents[1] / "main.py"
    development = executable.stem.lower() in {"python", "pythonw"}
    if development:
        executable = executable.with_name("pythonw.exe")
    script = Path(__file__).with_name("lunaris_link.ps1").read_text(encoding="utf-8")
    script = script.replace("@@CLIENT@@", literal(executable)).replace(
        "@@ENTRY@@", literal(source) if development else "''").replace(
        "@@INBOX@@", literal(directory / "imports"))
    launcher = directory / "lunaris-link.ps1"
    atomic_write(launcher, b"\xef\xbb\xbf" + script.encode("utf-8"))
    powershell = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32/WindowsPowerShell/v1.0/powershell.exe"
    command = subprocess.list2cmdline([str(powershell), "-NoProfile", "-NonInteractive",
        "-WindowStyle", "Hidden", "-ExecutionPolicy", "Bypass", "-File", str(launcher)]) + ' "%1"'
    with winreg.CreateKey(winreg.HKEY_CURRENT_USER, r"Software\Classes\lunaris") as key:
        winreg.SetValueEx(key, "", 0, winreg.REG_SZ, "URL:Lunaris client")
        winreg.SetValueEx(key, "URL Protocol", 0, winreg.REG_SZ, "")
        with winreg.CreateKey(key, r"shell\open\command") as action:
            winreg.SetValueEx(action, "", 0, winreg.REG_SZ, command)


def take_import_link(directory: Path) -> str | None:
    inbox = directory / "imports"
    for path in sorted(inbox.glob("*.link"), key=lambda p: p.name):
        try:
            if time.time() - path.stat().st_mtime > 120 or path.stat().st_size > 100000:
                continue
            return dpapi(path.read_bytes(), decrypt=True).decode("utf-8")
        except (OSError, ValueError, UnicodeError, UserError):
            continue
        finally:
            path.unlink(missing_ok=True)
    return None
