"""Windows Job Object, single-instance lock and transactional WinINET proxy."""
from __future__ import annotations

import ctypes
import json
import os
import subprocess
import time
from ctypes import wintypes
from pathlib import Path

from .models import UserError
from .storage import atomic_write, dpapi


class SingleInstance:
    def __init__(self, name: str):
        self.kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        self.kernel.CreateMutexW.argtypes = [ctypes.c_void_p, wintypes.BOOL, wintypes.LPCWSTR]
        self.kernel.CreateMutexW.restype = wintypes.HANDLE
        self.kernel.CloseHandle.argtypes = [wintypes.HANDLE]
        self.handle = self.kernel.CreateMutexW(None, False, name)
        if not self.handle:
            raise UserError("Не удалось создать блокировку приложения.")
        if ctypes.get_last_error() == 183:
            self.close()
            raise UserError("Lunaris client уже запущен. Закройте другой экземпляр приложения.")

    def close(self):
        if self.handle:
            self.kernel.CloseHandle(self.handle)
            self.handle = None


class JobObject:
    def __init__(self):
        class Basic(ctypes.Structure):
            _fields_ = [("PerProcessUserTimeLimit", ctypes.c_int64), ("PerJobUserTimeLimit", ctypes.c_int64),
                        ("LimitFlags", wintypes.DWORD), ("MinimumWorkingSetSize", ctypes.c_size_t),
                        ("MaximumWorkingSetSize", ctypes.c_size_t), ("ActiveProcessLimit", wintypes.DWORD),
                        ("Affinity", ctypes.c_size_t), ("PriorityClass", wintypes.DWORD), ("SchedulingClass", wintypes.DWORD)]

        class Counters(ctypes.Structure):
            _fields_ = [(key, ctypes.c_uint64) for key in ["ReadOperationCount", "WriteOperationCount", "OtherOperationCount", "ReadTransferCount", "WriteTransferCount", "OtherTransferCount"]]

        class Extended(ctypes.Structure):
            _fields_ = [("BasicLimitInformation", Basic), ("IoInfo", Counters),
                        ("ProcessMemoryLimit", ctypes.c_size_t), ("JobMemoryLimit", ctypes.c_size_t),
                        ("PeakProcessMemoryUsed", ctypes.c_size_t), ("PeakJobMemoryUsed", ctypes.c_size_t)]

        self.kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        self.kernel.CreateJobObjectW.argtypes = [ctypes.c_void_p, wintypes.LPCWSTR]
        self.kernel.CreateJobObjectW.restype = wintypes.HANDLE
        self.kernel.SetInformationJobObject.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD]
        self.kernel.AssignProcessToJobObject.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
        self.kernel.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
        self.kernel.OpenProcess.restype = wintypes.HANDLE
        self.kernel.CloseHandle.argtypes = [wintypes.HANDLE]
        self.handle = self.kernel.CreateJobObjectW(None, None)
        limits = Extended()
        limits.BasicLimitInformation.LimitFlags = 0x2000  # JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        if not self.handle or not self.kernel.SetInformationJobObject(self.handle, 9, ctypes.byref(limits), ctypes.sizeof(limits)):
            self.close()
            raise UserError("Windows не разрешил защиту процесса ядра Job Object.")

    def assign(self, pid: int):
        process = self.kernel.OpenProcess(0x100 | 0x1, False, pid)  # SET_QUOTA | TERMINATE
        if not process:
            raise UserError("Не удалось взять процесс ядра под контроль.")
        try:
            if not self.kernel.AssignProcessToJobObject(self.handle, process):
                raise UserError("Не удалось привязать процесс ядра к приложению.")
        finally:
            self.kernel.CloseHandle(process)

    def close(self):
        if getattr(self, "handle", None):
            self.kernel.CloseHandle(self.handle)
            self.handle = None


class WindowsProxy:
    NAMES = ["ProxyEnable", "ProxyServer", "ProxyOverride", "AutoConfigURL"]

    def __init__(self, directory: Path):
        self.journal = directory / "proxy.dpapi"
        self.guardian = None

    @staticmethod
    def _key():
        import winreg
        return winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Internet Settings", 0, winreg.KEY_QUERY_VALUE | winreg.KEY_SET_VALUE)

    @staticmethod
    def _read(key, name):
        import winreg
        try:
            value, kind = winreg.QueryValueEx(key, name)
            return [value, kind]
        except FileNotFoundError:
            return None

    @staticmethod
    def _write(key, name, value):
        import winreg
        if value is None:
            try:
                winreg.DeleteValue(key, name)
            except FileNotFoundError:
                pass
        else:
            winreg.SetValueEx(key, name, 0, value[1], value[0])

    @staticmethod
    def _notify():
        wininet = ctypes.WinDLL("wininet", use_last_error=True)
        wininet.InternetSetOptionW(None, 39, None, 0)
        wininet.InternetSetOptionW(None, 37, None, 0)

    def apply(self, port: int):
        import winreg
        self.restore()
        applied = {"ProxyEnable": [1, winreg.REG_DWORD],
                   "ProxyServer": [f"http=127.0.0.1:{port};https=127.0.0.1:{port};socks=127.0.0.1:{port}", winreg.REG_SZ],
                   "ProxyOverride": ["<local>;localhost;127.*;[::1]", winreg.REG_SZ], "AutoConfigURL": None}
        with self._key() as key:
            previous = {name: self._read(key, name) for name in self.NAMES}
            atomic_write(self.journal, dpapi(json.dumps({"previous": previous, "applied": applied}).encode()))
        # Guardian must be ready before changing WinINET. A failed helper launch aborts activation.
        script = Path(__file__).with_name("proxy_guardian.ps1")
        ready = self.journal.with_suffix(".ready")
        ready.unlink(missing_ok=True)
        self.guardian = subprocess.Popen([
            "powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", str(script),
            "-ParentId", str(os.getpid()), "-Journal", str(self.journal), "-Ready", str(ready),
        ], creationflags=subprocess.CREATE_NO_WINDOW, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        deadline = time.monotonic() + 8
        while not ready.exists():
            if self.guardian.poll() is not None or time.monotonic() >= deadline:
                self.restore()
                raise UserError("Не удалось запустить восстановление системного прокси. Прокси не включён.")
            time.sleep(0.05)
        ready.unlink(missing_ok=True)
        with self._key() as key:
            for name, value in applied.items():
                self._write(key, name, value)
        self._notify()

    def restore(self):
        if not self.journal.exists():
            return
        try:
            record = json.loads(dpapi(self.journal.read_bytes(), decrypt=True))
            with self._key() as key:
                for name in self.NAMES:
                    current = self._read(key, name)
                    # Preserve a subsequent change made by the user or another program.
                    if current == record["applied"][name]:
                        self._write(key, name, record["previous"][name])
            self._notify()
            self.journal.unlink(missing_ok=True)
            if self.guardian and self.guardian.poll() is None:
                self.guardian.terminate()
                self.guardian.wait(timeout=5)
            self.guardian = None
        except (OSError, ValueError, subprocess.TimeoutExpired):
            raise UserError("Не удалось восстановить системный прокси. Журнал восстановления сохранён.") from None
