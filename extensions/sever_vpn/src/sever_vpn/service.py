from dataclasses import dataclass
from typing import Optional

import flet as ft


@dataclass
class VpnStateEvent(ft.Event["VpnBridge"]):
    status: str = "disconnected"
    error: Optional[str] = None
    upload: int = 0
    download: int = 0
    duration: int = 0


@ft.control("SeverVpn")
class VpnBridge(ft.Service):
    on_state: Optional[ft.EventHandler[VpnStateEvent]] = None

    async def connect(self, config: str, probe_url: str, server_name: str = "", *, verify_connection: bool = True) -> dict:
        return await self._invoke_method("connect", {"config": config, "probe_url": probe_url,
            "server_name": server_name, "verify_connection": verify_connection}, timeout=120)

    async def disconnect(self) -> dict:
        # Native IPC completes after TUN and both cores have actually stopped.
        return await self._invoke_method("disconnect", timeout=45)

    async def snapshot(self) -> dict:
        return await self._invoke_method("snapshot", timeout=10)

    async def take_import_link(self) -> str | None:
        return await self._invoke_method("take_import_link", timeout=10)

    async def vault(self, method: str, data: str) -> str:
        return await self._invoke_method(method, {"data": data}, timeout=15)
