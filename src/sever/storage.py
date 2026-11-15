from __future__ import annotations

import asyncio
import base64
import ctypes
import json
import os
import secrets
import sys
from pathlib import Path
from typing import Protocol

from .models import Settings, State, UserError

# Preserve the existing vault format and paths across the Lunaris client rename.
MAGIC = b"SEVER2\0"


def atomic_write(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_name(path.name + ".tmp")
    with open(temp, "wb") as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temp, path)


def dpapi(data: bytes, *, decrypt: bool = False) -> bytes:
    if sys.platform != "win32":
        raise UserError("Windows DPAPI недоступен на этой платформе.")
    from ctypes import wintypes

    class Blob(ctypes.Structure):
        _fields_ = [("size", wintypes.DWORD), ("data", ctypes.POINTER(ctypes.c_ubyte))]

    buffer = ctypes.create_string_buffer(data)
    source = Blob(len(data), ctypes.cast(buffer, ctypes.POINTER(ctypes.c_ubyte)))
    target = Blob()
    crypt = ctypes.WinDLL("crypt32", use_last_error=True)
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.LocalFree.argtypes = [ctypes.c_void_p]
    kernel.LocalFree.restype = ctypes.c_void_p
    if decrypt:
        ok = crypt.CryptUnprotectData(ctypes.byref(source), None, None, None, None, 1, ctypes.byref(target))
    else:
        ok = crypt.CryptProtectData(ctypes.byref(source), "Lunaris client", None, None, None, 1, ctypes.byref(target))
    if not ok:
        raise UserError("Не удалось получить доступ к защищённому хранилищу Windows.")
    try:
        return ctypes.string_at(target.data, target.size)
    finally:
        kernel.LocalFree(target.data)


class Vault(Protocol):
    async def encrypt(self, data: bytes) -> bytes: ...
    async def decrypt(self, data: bytes) -> bytes: ...


class WindowsVault:
    def __init__(self, directory: Path):
        self.directory = directory

    async def encrypt(self, data: bytes) -> bytes:
        return await asyncio.to_thread(dpapi, data)

    async def decrypt(self, data: bytes) -> bytes:
        return await asyncio.to_thread(dpapi, data, decrypt=True)


class AndroidVault:
    def __init__(self, bridge):
        self.bridge = bridge

    async def _invoke(self, name: str, data: bytes) -> bytes:
        try:
            value = await self.bridge.vault(name, base64.b64encode(data).decode())
            if not isinstance(value, str):
                raise ValueError
            return base64.b64decode(value, validate=True)
        except Exception:
            raise UserError("Android Keystore недоступен. Секреты не будут сохранены открытым текстом.") from None

    async def encrypt(self, data: bytes) -> bytes:
        return await self._invoke("vault_encrypt", data)

    async def decrypt(self, data: bytes) -> bytes:
        return await self._invoke("vault_decrypt", data)


class Repository:
    def __init__(self, directory: Path, vault: Vault, *, default_core: str = "sing-box"):
        self.directory = directory
        self.path = directory / "state.enc"
        self.vault = vault
        self.default_core = default_core
        self.state = State(settings=Settings(core=default_core))
        self.lock = asyncio.Lock()
        self._loaded = False

    async def load(self) -> None:
        if self.path.exists():
            try:
                data = await asyncio.to_thread(self.path.read_bytes)
                if not data.startswith(MAGIC):
                    raise ValueError
                plain = await self.vault.decrypt(data[len(MAGIC):])
                self.state = State.from_dict(json.loads(plain), default_core=self.default_core)
                self.state.settings.validate()
            except Exception:
                raise UserError("Хранилище повреждено или недоступно. Исходный файл сохранён.") from None
        self._loaded = True

    async def commit(self, state: State) -> None:
        """Call under lock. Publish in-memory state only after the atomic write succeeds."""
        if not self._loaded:
            raise UserError("Защищённое хранилище ещё не открыто.")
        plain = json.dumps(state.to_dict(), ensure_ascii=False, separators=(",", ":")).encode()
        data = MAGIC + await self.vault.encrypt(plain)
        try:
            await asyncio.to_thread(atomic_write, self.path, data)
        except OSError:
            raise UserError("Не удалось сохранить данные. Изменения не применены.") from None
        self.state = state


def data_directory() -> Path:
    if sys.platform == "win32":
        return Path(os.environ.get("LOCALAPPDATA", str(Path.home()))) / "SeverVPN"
    # Flet's packaged Android runtime sets FLET_APP_STORAGE_DATA to the private app directory.
    value = os.environ.get("FLET_APP_STORAGE_DATA")
    if value:
        return Path(value) / "sever"
    raise UserError("Нет приватной директории приложения. Запустите нативную Windows или Android сборку.")
