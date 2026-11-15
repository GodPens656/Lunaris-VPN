"""Render country flag emoji with bundled SVGs, including on Windows."""
from functools import lru_cache
from pathlib import Path
import re

import flet as ft

_FLAGS = Path(__file__).with_name("flag_assets")
_FLAG = re.compile(r"[\U0001F1E6-\U0001F1FF]{2}\uFE0F?")


@lru_cache(maxsize=258)
def _flag_svg(code: str) -> bytes | None:
    path = _FLAGS / f"{code}.svg"
    return path.read_bytes() if path.is_file() else None


def flag_text(value: str, *, size=14, color=None, weight=None):
    """Keep names as text and display their flag emoji as offline images."""
    images = []

    def replace(match):
        code = "".join(chr(ord(c) - 0x1F1E6 + ord("A")) for c in match[0][:2])
        svg = _flag_svg(code)
        if svg is None:
            return match[0]
        images.append(ft.Image(src=svg, width=size * 1.5, height=size * 1.5,
                               semantics_label=f"Флаг {code}"))
        return ""

    label = _FLAG.sub(replace, value)
    if not images:
        return ft.Text(value, size=size, color=color, weight=weight)
    return ft.Row([*images, ft.Text(label.strip(), size=size, color=color,
                                 weight=weight, expand=True)], spacing=6,
                  vertical_alignment=ft.CrossAxisAlignment.CENTER)
