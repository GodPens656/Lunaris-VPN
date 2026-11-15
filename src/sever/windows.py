from __future__ import annotations

import asyncio
import ctypes
import ipaddress
import json
import secrets
import socket
import subprocess
import time
import copy
import tempfile
from pathlib import Path

import httpx

from . import CORE_VERSION
from .config import build_config
from .core import ObservableCore
from .models import Profile, Settings, Stats, Status, UserError
from .mihomo import MIHOMO_VERSION, build_mihomo_config
from .storage import atomic_write
from .windows_native import JobObject, WindowsProxy
from .xray import XRAY_VERSION, build_xray_config, sidecar_outbound
from .latency import LatencyResult, proxy_get_latency


def available_ports(*ports: int) -> None:
    sockets = []
    try:
        for port in ports:
            sock = socket.socket()
            sockets.append(sock)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
            sock.bind(("127.0.0.1", port))
    except OSError:
        raise UserError("Локальный порт занят. Измените порты в настройках или остановите другой прокси.") from None
    finally:
        for sock in sockets:
            sock.close()


def free_proxy_port(*excluded: int) -> int:
    """Xray SOCKS binds TCP and UDP; a TCP-only probe misses Windows UDP exclusions."""
    for _ in range(128):
        candidate = 1024 + secrets.randbelow(65536 - 1024)
        if candidate in excluded:
            continue
        with socket.socket() as tcp, socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
            try:
                for sock in (tcp, udp):
                    sock.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
                    sock.bind(("127.0.0.1", candidate))
            except OSError:
                continue
            return candidate
    raise UserError("Не удалось выбрать свободный локальный TCP/UDP-порт для прокси.")


async def resolve_bootstrap(profile: Profile, settings: Settings) -> dict:
    """Resolve just the VPN endpoint before Windows TUN blocks physical DNS."""
    hostname = profile.outbound["server"]
    try:
        ipaddress.ip_address(hostname)
        return {}
    except ValueError:
        pass
    args = ["powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
            "-File", str(Path(__file__).with_name("resolve_bootstrap.ps1")),
            "-Name", hostname, "-Server", settings.bootstrap_dns]
    if not settings.ipv6:
        args.append("-IPv4Only")
    process = await asyncio.create_subprocess_exec(*args, stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.DEVNULL, creationflags=subprocess.CREATE_NO_WINDOW)
    try:
        output, _ = await asyncio.wait_for(process.communicate(), 15)
    except (TimeoutError, asyncio.CancelledError) as error:
        if process.returncode is None:
            process.kill()
        await process.wait()
        if isinstance(error, asyncio.CancelledError):
            raise
        raise UserError("Не удалось разрешить адрес VPN-сервера до запуска TUN: Bootstrap DNS не ответил. Проверьте Bootstrap DNS в настройках.") from None
    try:
        values = json.loads(output)
        if process.returncode or not isinstance(values, list):
            raise ValueError
        addresses = list(dict.fromkeys(str(ipaddress.ip_address(value)) for value in values))
        addresses = [value for value in addresses if settings.ipv6 or ipaddress.ip_address(value).version == 4]
        if not addresses:
            raise ValueError
    except (ValueError, TypeError):
        raise UserError("Не удалось разрешить адрес VPN-сервера до запуска TUN. Проверьте адрес сервера и Bootstrap DNS в настройках.") from None
    # Both cores retain the hostname (and therefore SNI/Host) in their outbound.
    return {hostname: sorted(addresses, key=lambda value: ipaddress.ip_address(value).version)}


class WindowsCore(ObservableCore):
    def __init__(self, directory: Path, log, *, probe_only: bool = False):
        super().__init__(log)
        self.directory = directory
        self.proxy = None if probe_only else WindowsProxy(directory)
        self.probe_only = probe_only
        self.process = None
        self.job = None
        self.client: httpx.AsyncClient | None = None
        self.lock = asyncio.Lock()
        self._tasks: list[asyncio.Task] = []
        self._stopping = False
        self._config_path: Path | None = None
        self.xray_process = None
        self._xray_config_path: Path | None = None

    @staticmethod
    def core_path(settings: Settings) -> Path:
        import os
        custom_path = settings.mihomo_path if settings.core == "mihomo" else settings.core_path
        if custom_path:
            return Path(custom_path).expanduser().resolve()
        assets = Path(os.environ.get("LUNARIS_ASSETS_DIR", os.environ.get("FLET_ASSETS_DIR", str(Path(__file__).resolve().parents[2] / "assets"))))
        return assets / "core" / ("mihomo.exe" if settings.core == "mihomo" else "sing-box.exe")

    @staticmethod
    def xray_path(settings: Settings) -> Path:
        adjacent = WindowsCore.core_path(settings).parent / "xray.exe"
        if adjacent.is_file():
            return adjacent
        return WindowsCore.core_path(Settings()).parent / "xray.exe"

    async def _start_xray(self, profile, settings, endpoint_hosts=None):
        executable = self.xray_path(settings)
        if not executable.is_file():
            raise UserError("Для этого сервера нужен xray.exe. Выполните scripts/fetch_core.py windows и пересоберите приложение.")
        version = await self._command(executable, "version")
        if not version.startswith(f"Xray {XRAY_VERSION} "):
            raise UserError("Нужен Xray 26.3.27 из проверенного комплекта ядер.")
        port = free_proxy_port(settings.mixed_port, settings.api_port)
        password = secrets.token_urlsafe(32)
        config = build_xray_config(profile, port, password, settings, endpoint_hosts=endpoint_hosts)
        self.log.register(config)
        self._xray_config_path = self.directory / f"session-xray-{secrets.token_hex(8)}.json"
        await asyncio.to_thread(atomic_write, self._xray_config_path, json.dumps(config).encode())
        await self._command(executable, "run", "-test", "-c", str(self._xray_config_path))
        self.xray_process = await asyncio.create_subprocess_exec(str(executable), "run", "-c", str(self._xray_config_path),
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT, creationflags=subprocess.CREATE_NO_WINDOW)
        self.job.assign(self.xray_process.pid)
        self._tasks.append(asyncio.create_task(self._read_logs(self.xray_process)))
        for _ in range(80):
            if self.xray_process.returncode is not None:
                raise UserError("Xray завершился во время запуска. Проверьте журнал.")
            try:
                reader, writer = await asyncio.wait_for(asyncio.open_connection("127.0.0.1", port), 0.2)
                writer.close()
                await writer.wait_closed()
                self._tasks.append(asyncio.create_task(self._monitor(self.xray_process)))
                return sidecar_outbound(port, password)
            except (OSError, TimeoutError):
                await asyncio.sleep(0.05)
        raise UserError("Xray не открыл локальный порт.")

    async def _command(self, executable: Path, *args: str) -> str:
        process = await asyncio.create_subprocess_exec(str(executable), *args, stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT, creationflags=subprocess.CREATE_NO_WINDOW)
        try:
            output, _ = await asyncio.wait_for(process.communicate(), 15)
        except (TimeoutError, asyncio.CancelledError):
            process.kill()
            await process.wait()
            raise
        if process.returncode:
            self.log.add(output.decode(errors="replace"))
            raise UserError("Ядро отклонило конфигурацию. Подробности доступны в очищенном журнале.")
        return output.decode(errors="replace")

    async def connect(self, profile: Profile, settings: Settings) -> None:
        async with self.lock:
            if self.process or self.xray_process:
                raise UserError("Сначала отключите текущее соединение.")
            settings.validate()
            if self.probe_only and settings.mode != "proxy":
                raise UserError("Проверка сервера допускает только локальный прокси.")
            self.publish(Status.CONNECTING)
            self.stats = Stats()
            self._stopping = False
            try:
                settings = self.prepare_settings(profile, settings)
                executable = self.core_path(settings)
                if not executable.is_file():
                    raise UserError(f"{settings.core}.exe не найден. Выполните scripts/fetch_core.py windows или укажите путь в настройках.")
                mihomo = settings.core == "mihomo"
                version = await self._command(executable, "-v" if mihomo else "version")
                if mihomo and not version.startswith(f"Mihomo Meta v{MIHOMO_VERSION} "):
                    raise UserError(f"Нужен Mihomo {MIHOMO_VERSION} из проверенного комплекта ядер.")
                if not mihomo and f"sing-box version {CORE_VERSION}\n" not in version.replace("\r\n", "\n"):
                    raise UserError("Нужен sing-box 1.14.0. Версия ядра не совпадает с проверенной конфигурацией.")
                if settings.mode == "tun" and not ctypes.windll.shell32.IsUserAnAdmin():
                    raise UserError("TUN требует запуска приложения от имени администратора.")
                await asyncio.to_thread(available_ports, settings.mixed_port, settings.api_port)
                endpoint_hosts = await resolve_bootstrap(profile, settings) if settings.mode == "tun" else None
                if endpoint_hosts:
                    self.log.add("Адрес VPN-сервера разрешён до запуска TUN; начальный DNS не требует выхода на порт 53 после запуска туннеля.")
                secret = secrets.token_urlsafe(32)
                # The runtime config necessarily contains credentials. Restrict the directory ACL first.
                self.directory.mkdir(parents=True, exist_ok=True)
                await self._restrict_runtime()
                self.job = JobObject()
                if mihomo:
                    config = build_mihomo_config(profile, settings, secret, endpoint_hosts=endpoint_hosts)
                else:
                    sidecar = await self._start_xray(profile, settings, endpoint_hosts) if profile.requires_xray else None
                    config = build_config(profile, settings, secret, sidecar=sidecar, endpoint_hosts=endpoint_hosts)
                self.log.register(config)
                self._config_path = self.directory / f"session-{secrets.token_hex(8)}.json"
                await asyncio.to_thread(atomic_write, self._config_path, json.dumps(config).encode())
                check_args = ("-t", "-d", str(self.directory), "-f", str(self._config_path)) if mihomo else ("check", "-c", str(self._config_path))
                run_args = ("-d", str(self.directory), "-f", str(self._config_path)) if mihomo else ("run", "-c", str(self._config_path))
                await self._command(executable, *check_args)
                self.process = await asyncio.create_subprocess_exec(str(executable), *run_args,
                    stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT, creationflags=subprocess.CREATE_NO_WINDOW)
                self.job.assign(self.process.pid)
                self._tasks.append(asyncio.create_task(self._read_logs(self.process)))
                self.client = httpx.AsyncClient(base_url=f"http://127.0.0.1:{settings.api_port}",
                    headers={"Authorization": f"Bearer {secret}"}, timeout=15, trust_env=False)
                ready = False
                deadline = time.monotonic() + 12
                while time.monotonic() < deadline:
                    if self.process.returncode is not None or (self.xray_process and self.xray_process.returncode is not None):
                        raise UserError("Ядро завершилось во время запуска. Проверьте журнал.")
                    try:
                        response = await self.client.get("/version", timeout=1)
                        response.raise_for_status()
                        reader, writer = await asyncio.wait_for(asyncio.open_connection("127.0.0.1", settings.mixed_port), 1)
                        writer.close()
                        await writer.wait_closed()
                        ready = True
                        break
                    except (httpx.HTTPError, OSError, TimeoutError):
                        await asyncio.sleep(0.15)
                if not ready:
                    raise UserError("Ядро не подтвердило запуск API управления и локального прокси.")
                # The selected core makes this request through the selected outbound.
                if not self.probe_only and settings.verify_connection:
                    result = await self.client.get("/proxies/proxy/delay", params={"url": settings.probe_url, "timeout": "10000"})
                    if result.status_code != 200 or not isinstance(result.json().get("delay"), (int, float)):
                        self.log.add(f"HTTPS-проверка ядра: HTTP {result.status_code}; {result.text}")
                        raise UserError("Сервер не прошёл проверку HTTPS через ядро. Подключение не подтверждено.")
                if settings.mode == "proxy" and self.proxy is not None:
                    await asyncio.to_thread(self.proxy.apply, settings.mixed_port)
                self.started_at = time.monotonic()
                self.publish(Status.CONNECTED)
                if not self.probe_only:
                    if settings.verify_connection:
                        self.log.add("Ядро подтвердило HTTPS-соединение через выбранный сервер.")
                    else:
                        self.log.add("HTTPS-проверка при подключении отключена. Ядро запущено; доступ к интернету не проверялся.")
                self._tasks.append(asyncio.create_task(self._monitor(self.process)))
            except asyncio.CancelledError:
                await self._cleanup()
                self.publish(Status.DISCONNECTED)
                raise
            except Exception as error:
                message = str(error) if isinstance(error, UserError) else "Ошибка запуска ядра. Проверьте установленное ядро и настройки."
                cleanup_error = await self._cleanup()
                message = cleanup_error or message
                self.publish(Status.ERROR, message)
                raise UserError(message) from None

    async def _restrict_runtime(self):
        # SID-based ACL avoids localized account names and prevents access by other ordinary users.
        who = await asyncio.create_subprocess_exec("whoami.exe", "/user", "/fo", "csv", "/nh",
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL, creationflags=subprocess.CREATE_NO_WINDOW)
        output, _ = await who.communicate()
        import re
        match = re.search(rb"S-1-5-21-(?:\d+-){2}\d+-\d+", output)
        if not match:
            raise UserError("Не удалось определить пользователя для защиты временной конфигурации.")
        sid = match[0].decode()
        acl = await asyncio.create_subprocess_exec("icacls.exe", str(self.directory), "/inheritance:r", "/grant:r",
            f"*{sid}:(OI)(CI)F", "*S-1-5-18:(OI)(CI)F", stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL, creationflags=subprocess.CREATE_NO_WINDOW)
        if await acl.wait() != 0:
            raise UserError("Не удалось защитить каталог временной конфигурации.")

    async def _read_logs(self, process):
        try:
            while line := await process.stdout.readline():
                self.log.add(line.decode(errors="replace").strip())
        except (asyncio.CancelledError, ValueError):
            pass

    async def _monitor(self, process):
        await process.wait()
        if not self._stopping:
            async with self.lock:
                if self._stopping:
                    return
                cleanup_error = await self._cleanup()
                self.publish(Status.ERROR, cleanup_error or "Ядро аварийно завершилось. Соединение остановлено, настройки прокси восстановлены.")

    async def get_stats(self) -> Stats:
        if self.status == Status.CONNECTED and self.client:
            try:
                response = await self.client.get("/connections", timeout=2)
                response.raise_for_status()
                body = response.json()
                self.stats.upload = int(body["uploadTotal"])
                self.stats.download = int(body["downloadTotal"])
            except (httpx.HTTPError, ValueError, KeyError):
                # Lost control API is a real failure; do not retain a stale connected label.
                async with self.lock:
                    if self.status == Status.CONNECTED:
                        await self._cleanup()
                        self.publish(Status.ERROR, "Потеряна связь с ядром. Соединение остановлено.")
        return await super().get_stats()

    async def _cleanup(self):
        self._stopping = True
        cleanup_error = None
        for process in (self.process, self.xray_process):
            if process and process.returncode is None:
                try:
                    process.terminate()
                    await asyncio.wait_for(process.wait(), 5)
                except TimeoutError:
                    process.kill()
                    await process.wait()
                except ProcessLookupError:
                    pass
        self.process = None
        self.xray_process = None
        if self.job:
            self.job.close()
            self.job = None
        for task in self._tasks:
            if task is not asyncio.current_task():
                task.cancel()
        self._tasks = []
        if self.client:
            await self.client.aclose()
            self.client = None
        try:
            if self.proxy is not None:
                await asyncio.to_thread(self.proxy.restore)
        except UserError as error:
            cleanup_error = str(error)
            self.log.add(cleanup_error)
        if self._config_path:
            self._config_path.unlink(missing_ok=True)
            self._config_path = None
        if self._xray_config_path:
            self._xray_config_path.unlink(missing_ok=True)
            self._xray_config_path = None
        self.started_at = None
        return cleanup_error

    async def disconnect(self) -> None:
        async with self.lock:
            self.publish(Status.DISCONNECTING)
            error = await self._cleanup()
            self.publish(Status.ERROR if error else Status.DISCONNECTED, error)

    async def recover(self):
        if self.proxy is not None:
            await asyncio.to_thread(self.proxy.restore)
        # Single-instance mutex is held; only stale session configs can exist here.
        if self.directory.exists():
            for path in self.directory.glob("session-*.json"):
                path.unlink(missing_ok=True)

    async def probe_profile(self, profile: Profile, settings: Settings) -> LatencyResult:
        """Use a separate loopback proxy; never apply/restore WinINET or start TUN."""
        from .redaction import SafeLog

        snapshot = copy.deepcopy(settings)
        snapshot.mode = "proxy"
        snapshot.mixed_port = free_proxy_port()
        snapshot.api_port = free_proxy_port(snapshot.mixed_port)
        self.directory.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix="probe-", dir=self.directory) as directory:
            probe = WindowsCore(Path(directory), SafeLog(), probe_only=True)
            try:
                async with asyncio.timeout(30):
                    await probe.connect(copy.deepcopy(profile), snapshot)
                    return await proxy_get_latency(snapshot)
            except TimeoutError:
                return LatencyResult(error="Тайм-аут PROXY GET")
            except UserError:
                return LatencyResult(error="Прокси сервера недоступен")
            finally:
                await probe.disconnect()
