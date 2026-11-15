"""Bounded, independent latency probes without changing the VPN connection."""
from __future__ import annotations

import asyncio
import hashlib
import locale
import re
import secrets
import subprocess
import sys
import time
from dataclasses import dataclass
from collections.abc import Awaitable, Callable

import httpx

from .models import Profile, Settings
from .quic_probe import initial_probe, is_probe_reply

PROBE_TIMEOUT = 5.0


@dataclass(frozen=True)
class LatencyResult:
    milliseconds: float | None = None
    error: str | None = None
    upper_bound: bool = False

    @property
    def label(self) -> str:
        if self.milliseconds is not None:
            return f"{'<' if self.upper_bound else ''}{self.milliseconds:.1f} мс"
        return self.error or "Нет результата"


async def tcp_latency(host: str, port: int, *, timeout: float = PROBE_TIMEOUT) -> LatencyResult:
    writer = None
    try:
        async with asyncio.timeout(timeout):
            started = time.perf_counter()
            _, writer = await asyncio.open_connection(host, port)
            return LatencyResult((time.perf_counter() - started) * 1000)
    except TimeoutError:
        return LatencyResult(error="Тайм-аут TCP")
    except OSError:
        return LatencyResult(error="TCP-порт недоступен")
    finally:
        if writer is not None:
            writer.close()
            try:
                await asyncio.wait_for(writer.wait_closed(), 1)
            except (OSError, TimeoutError):
                pass


def transport_label(profile: Profile) -> str:
    return "UDP" if profile.protocol == "hysteria2" else "TCP"


def _salamander_payload(data: bytes, password: str, salt: bytes) -> bytes:
    # Hysteria 2: BLAKE2b-256(password + salt), repeated XOR over the payload.
    mask = hashlib.blake2b(password.encode("utf-8") + salt, digest_size=32).digest()
    return bytes(value ^ mask[index % 32] for index, value in enumerate(data))


async def udp_latency(
    host: str, port: int, *, obfs_password: str | None = None,
    timeout: float = PROBE_TIMEOUT,
) -> LatencyResult:
    """Measure an authenticated QUIC Initial/Retry reply, including DNS.

    Sending a UDP datagram alone cannot establish reachability. Use a real
    Initial, since Hysteria servers can disable Version Negotiation with obfs.
    This measures transport reachability, without authenticating to the VPN.
    """
    transport = None
    loop = asyncio.get_running_loop()
    reply = loop.create_future()
    destination, source = secrets.token_bytes(8), secrets.token_bytes(8)
    packet = initial_probe(destination, source)
    if obfs_password is not None:
        salt = secrets.token_bytes(8)
        packet = salt + _salamander_payload(packet, obfs_password, salt)

    class Probe(asyncio.DatagramProtocol):
        def datagram_received(self, data, _address):
            if reply.done():
                return
            if obfs_password is not None:
                if len(data) < 8:
                    return
                data = _salamander_payload(data[8:], obfs_password, data[:8])
            if not is_probe_reply(data, destination, source):
                return
            reply.set_result(time.perf_counter())

        def error_received(self, error):
            if not reply.done():
                reply.set_exception(error)

        def connection_lost(self, error):
            if not reply.done():
                reply.set_exception(error or OSError("UDP transport closed"))

    try:
        async with asyncio.timeout(timeout):
            started = time.perf_counter()
            transport, _ = await loop.create_datagram_endpoint(Probe, remote_addr=(host, port))
            transport.sendto(packet)
            received = await reply
            return LatencyResult((received - started) * 1000)
    except TimeoutError:
        return LatencyResult(error="Тайм-аут UDP")
    except (OSError, NotImplementedError):
        return LatencyResult(error="UDP-порт недоступен")
    finally:
        reply.cancel()
        if transport is not None:
            transport.close()


async def transport_latency(profile: Profile) -> LatencyResult:
    host, port = profile.outbound["server"], profile.outbound["server_port"]
    if profile.protocol == "hysteria2":
        obfs = profile.outbound.get("obfs", {})
        return await udp_latency(host, port, obfs_password=obfs.get("password"))
    return await tcp_latency(host, port)


def _icmp_reply(output: bytes) -> LatencyResult | None:
    # Windows ping uses the OEM code page; Linux/Android generally use UTF-8.
    for encoding in dict.fromkeys(("utf-8", "oem", locale.getencoding(), "cp866", "cp1251")):
        try:
            value = output.decode(encoding, errors="replace")
        except LookupError:
            continue
        reply = re.search(r"(?:time|время)\s*([=<])\s*(\d+(?:[.,]\d+)?)\s*(?:ms|мс)", value, re.IGNORECASE)
        if reply:
            # '<1ms' is an upper bound, not a measured zero.
            return LatencyResult(float(reply[2].replace(",", ".")), upper_bound=reply[1] == "<")
    return None


async def icmp_latency(host: str, *, timeout: float = PROBE_TIMEOUT) -> LatencyResult:
    process = None
    try:
        async with asyncio.timeout(timeout):
            # No shell: the imported endpoint is passed as a single argument.
            if sys.platform == "win32":
                command = ["ping", "-n", "1", "-w", str(int(timeout * 1000)), host]
                options = {"creationflags": subprocess.CREATE_NO_WINDOW}
            else:
                command = ["ping", "-n", "-c", "1", host]
                options = {}
            process = await asyncio.create_subprocess_exec(
                *command, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL, **options)
            output, _ = await process.communicate()
            reply = _icmp_reply(output)
            if process.returncode == 0 and reply is not None:
                return reply
            return LatencyResult(error="Нет ответа ICMP")
    except TimeoutError:
        return LatencyResult(error="Тайм-аут ICMP")
    except (OSError, NotImplementedError):
        return LatencyResult(error="ICMP недоступен")
    finally:
        if process is not None and process.returncode is None:
            try:
                process.kill()
            except ProcessLookupError:
                pass
            await process.communicate()


async def proxy_get_latency(settings: Settings, *, timeout: float = PROBE_TIMEOUT) -> LatencyResult:
    try:
        async with asyncio.timeout(timeout):
            async with httpx.AsyncClient(
                proxy=f"http://127.0.0.1:{settings.mixed_port}", trust_env=False,
                timeout=timeout, follow_redirects=False,
            ) as client:
                started = time.perf_counter()
                # Measure through response headers; never download an unbounded body.
                async with client.stream("GET", settings.probe_url) as response:
                    elapsed = (time.perf_counter() - started) * 1000
                    if not 200 <= response.status_code < 300:
                        return LatencyResult(error=f"HTTP {response.status_code}")
                    return LatencyResult(elapsed)
    except (TimeoutError, httpx.TimeoutException):
        return LatencyResult(error="Тайм-аут GET")
    except (httpx.HTTPError, OSError, ValueError):
        return LatencyResult(error="GET через прокси не выполнен")


async def measure_latency(profile: Profile, settings: Settings, *, proxy_connected: bool) -> dict[str, LatencyResult]:
    method = settings.latency_method
    if method == "tcp":
        result = await transport_latency(profile)
    elif method == "icmp":
        result = await icmp_latency(profile.outbound["server"])
    elif method == "proxy":
        result = await proxy_get_latency(settings) if proxy_connected else LatencyResult(error="Подключите VPN")
    else:
        raise ValueError("Invalid latency method")
    return {method: result}


async def measure_profiles(
    profiles: list[Profile], settings: Settings, method: str, *,
    proxy_probe: Callable[[Profile, Settings], Awaitable[LatencyResult]] | None = None,
    on_result: Callable[[str, LatencyResult], None] | None = None,
    concurrency: int = 8,
) -> dict[str, LatencyResult]:
    """Check a snapshot of the list with a bounded number of sockets/processes."""
    if method not in {"tcp", "icmp", "proxy"} or concurrency < 1:
        raise ValueError("Invalid latency method or concurrency")
    results = {}
    pending = iter(profiles)

    async def worker():
        for profile in pending:
            try:
                if method == "tcp":
                    result = await transport_latency(profile)
                elif method == "icmp":
                    result = await icmp_latency(profile.outbound["server"])
                elif proxy_probe is not None:
                    result = await proxy_probe(profile, settings)
                else:
                    result = LatencyResult(error="Проверка через прокси недоступна")
            except Exception:
                result = LatencyResult(error="Проверка не выполнена")
            results[profile.key] = result
            if on_result is not None:
                on_result(profile.key, result)

    async with asyncio.TaskGroup() as group:
        for _ in range(min(concurrency, len(profiles))):
            group.create_task(worker())
    return results
