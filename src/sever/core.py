from __future__ import annotations

import asyncio
import time
from dataclasses import replace
from typing import AsyncIterator, Protocol

from .models import Profile, Settings, Stats, Status
from .mihomo import MIHOMO_VERSION, effective_client_fingerprint
from .redaction import SafeLog


class CoreAdapter(Protocol):
    async def connect(self, profile: Profile, settings: Settings) -> None: ...
    async def disconnect(self) -> None: ...
    async def get_status(self) -> Status: ...
    async def get_stats(self) -> Stats: ...
    def events(self) -> AsyncIterator[Status]: ...


class ObservableCore:
    def __init__(self, log: SafeLog):
        self.status = Status.DISCONNECTED
        self.error: str | None = None
        self.log = log
        self.stats = Stats()
        self.started_at: float | None = None
        self.session_core: str | None = None
        self._listeners: set[asyncio.Queue] = set()

    def prepare_settings(self, profile: Profile, settings: Settings) -> Settings:
        settings.validate()
        if settings.core == "mihomo" and profile.requires_xray_grpc:
            # Preserve the saved core preference while using the only adapter
            # that can carry independent authority and the TunMulti wire format.
            settings = replace(settings, core="sing-box")
            self.log.add("gRPC mode=multi или authority требует Xray; для этого соединения используется sing-box / Xray.")
        if settings.core == "mihomo" and profile.options.get("spx", "/") != "/":
            self.log.add("Reality spx сохранён в профиле. Mihomo не использует обход сайта spiderX; авторизация Reality проверяется ядром.")
        if settings.core == "mihomo":
            fingerprint = profile.outbound.get("tls", {}).get("utls", {}).get("fingerprint")
            if effective_client_fingerprint(profile) != fingerprint:
                self.log.add(f"Reality ML-KEM: Mihomo {MIHOMO_VERSION} использует fingerprint chrome вместо {fingerprint}, "
                             "чтобы отправить X25519MLKEM768. Исходный профиль сохранён.")
        self.session_core = settings.core
        return settings

    def publish(self, status: Status, error: str | None = None) -> None:
        self.status, self.error = status, error
        if status == Status.DISCONNECTED:
            self.session_core = None
        if error:
            self.log.add(error)
        for queue in self._listeners:
            if queue.full():
                queue.get_nowait()
            queue.put_nowait(status)

    async def get_status(self) -> Status:
        return self.status

    async def get_stats(self) -> Stats:
        if self.started_at and self.status == Status.CONNECTED:
            self.stats.duration = int(time.monotonic() - self.started_at)
        return self.stats

    async def events(self) -> AsyncIterator[Status]:
        queue = asyncio.Queue(maxsize=10)
        self._listeners.add(queue)
        queue.put_nowait(self.status)
        try:
            while True:
                yield await queue.get()
        finally:
            self._listeners.discard(queue)
