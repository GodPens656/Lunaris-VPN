"""Use the app's own Windows icon in both Python and packaged launches."""
import os
from pathlib import Path
import subprocess
import sys


def assets_directory() -> Path:
    value = os.environ.get("FLET_ASSETS_DIR")
    return Path(value).resolve() if value else Path(__file__).resolve().parents[1] / "assets"


def prepare_windows_icon(assets: Path, *, force: bool = False) -> Path:
    """Generate ICO during development/builds; packaged apps just read it."""
    source, icon = assets / "icon.png", assets / "icon.ico"
    if icon.is_file() and (not source.is_file() or (
        not force and icon.stat().st_mtime_ns >= source.stat().st_mtime_ns
    )):
        return icon
    # This generator comes with flet-cli. It is not needed in the installed app.
    from flet_platform_assets import load_source, render_icons, write

    image, pre_rendered = load_source(source)
    result = render_icons(image, platform="windows", pre_rendered=pre_rendered, derived=True)
    result.ico = {"icon.ico": next(iter(result.ico.values()))}
    write(result, assets, declared_only=False)
    return icon


def configure_windows_launch() -> None:
    if sys.platform != "win32":
        return
    assets = assets_directory()
    development = Path(sys.executable).stem.lower() in {"python", "pythonw"}
    icon = prepare_windows_icon(assets) if development else assets / "icon.ico"
    if development:
        # Flet runs its UI in a separate flet.exe process. Give that window our
        # identity and a working pin target instead of inheriting Flet's icon.
        pythonw = Path(sys.executable).with_name("pythonw.exe")
        executable = pythonw if pythonw.is_file() else Path(sys.executable)
        entry = Path(__file__).resolve().parents[1] / "main.py"
        os.environ.update({
            "FLET_APP_USER_MODEL_ID": "dev.sever.LunarisVPN",
            "FLET_APP_RELAUNCH_COMMAND": subprocess.list2cmdline([str(executable), str(entry)]),
            "FLET_APP_RELAUNCH_DISPLAY_NAME": "Lunaris client",
            "FLET_APP_RELAUNCH_ICON": str(icon),
        })


def configure_window(page) -> None:
    if sys.platform == "win32" and not page.web:
        icon = assets_directory() / "icon.ico"
        if icon.is_file():
            page.window.icon = str(icon)

