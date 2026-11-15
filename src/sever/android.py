import json
import secrets
import asyncio

from .config import build_config
from .core import ObservableCore
from .models import Stats, Status, UserError
from .xray import build_xray_config, sidecar_outbound
from .mihomo import build_mihomo_sidecar

# The legacy Flet bridge is loaded only when explicitly requested. Tauri injects
# its own bridge, so Android production does not import Flutter/Flet packages.
VpnBridge = None


class AndroidCore(ObservableCore):
    def __init__(self, log, bridge=None):
        global VpnBridge
        super().__init__(log)
        if bridge is None:
            if VpnBridge is None:
                from sever_vpn import VpnBridge
            bridge = VpnBridge(on_state=self._event)
        self.bridge = bridge

    def _accept(self, snapshot):
        try:
            status = Status(snapshot.get("status", "error"))
        except (ValueError, AttributeError):
            status = Status.ERROR
            snapshot = {"error": "Android VPN-служба вернула некорректное состояние."}
        self.stats = Stats(int(snapshot.get("upload", 0)), int(snapshot.get("download", 0)), int(snapshot.get("duration", 0)))
        self.publish(status, snapshot.get("error"))

    async def _event(self, event):
        self._accept({"status": event.status, "error": event.error, "upload": event.upload, "download": event.download, "duration": event.duration})

    async def connect(self, profile, settings):
        self.publish(Status.CONNECTING)
        try:
            settings = self.prepare_settings(profile, settings)
            sidecar = None
            xray = None
            mihomo = None
            if settings.core == "mihomo":
                password = secrets.token_urlsafe(32)
                mihomo = build_mihomo_sidecar(profile, settings, password)
                sidecar = sidecar_outbound(0, password)
            elif profile.requires_xray:
                # The service reserves/replaces port 0 before starting either core.
                password = secrets.token_urlsafe(32)
                xray = build_xray_config(profile, 0, password, settings)
                sidecar = sidecar_outbound(0, password)
            config = build_config(profile, settings, secrets.token_urlsafe(32), android=True, sidecar=sidecar)
            if xray:
                config["sever_xray"] = xray
            if mihomo:
                config["sever_mihomo"] = mihomo
            self.log.register(config)
            result = await self.bridge.connect(json.dumps(config), settings.probe_url, server_name=profile.name,
                verify_connection=settings.verify_connection)
            self._accept(result)
            if not settings.verify_connection and self.status != Status.ERROR:
                self.log.add("HTTPS-проверка при подключении отключена. Доступ к интернету не проверяется.")
        except asyncio.CancelledError:
            raise
        except UserError as error:
            self.publish(Status.ERROR, str(error))
            raise
        except Exception:
            self.publish(Status.ERROR, "Android VPN-служба не ответила на запуск.")
            raise UserError(self.error) from None
        if self.status == Status.ERROR:
            raise UserError(self.error or "Android не запустил VPN-службу. Проверьте разрешение VPN и журнал состояния.")

    async def disconnect(self):
        self.publish(Status.DISCONNECTING)
        try:
            self._accept(await self.bridge.disconnect())
        except asyncio.CancelledError:
            raise
        except Exception:
            self.publish(Status.ERROR, "Android VPN-служба не подтвердила отключение. Повторите отключение.")
            raise UserError(self.error) from None

    async def get_status(self):
        self._accept(await self.bridge.snapshot())
        return self.status

    async def get_stats(self):
        await self.get_status()
        return self.stats
