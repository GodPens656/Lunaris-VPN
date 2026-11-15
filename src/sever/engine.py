"""UI-independent application API, shared by Tauri desktop and Android."""
from __future__ import annotations

import asyncio
import copy
from dataclasses import asdict, fields

from . import APP_VERSION, CORE_VERSION
from .deep_links import subscription_url
from .latency import measure_latency, measure_profiles
from .mihomo import MIHOMO_VERSION
from .models import Settings, Status, UserError
from .subscriptions import SubscriptionManager


class Engine:
    def __init__(self, repo, core, *, android=False):
        self.repo, self.core, self.android = repo, core, android
        self.manager = SubscriptionManager(repo)
        self.connection_lock = asyncio.Lock()
        self.stop = asyncio.Event()
        self.connect_task = None
        self.measure_task = None
        self.scheduler = None
        self.active_key = None
        self.results = {}
        self.measure_total = 0
        self.closed = False

    async def start(self):
        self.scheduler = asyncio.create_task(self.manager.scheduler(self.stop))
        if self.android:
            await self.core.get_status()

    def selected(self):
        return next((p for p in self.repo.state.profiles if p.key == self.repo.state.selected), None)

    def snapshot(self):
        # Connection credentials and subscription URLs never cross into the WebView.
        state = self.repo.state
        return {
            "version": APP_VERSION, "platform": "android" if self.android else "windows",
            "cores": {"sing-box": CORE_VERSION, "mihomo": MIHOMO_VERSION},
            "status": str(self.core.status), "error": self.core.error,
            "stats": asdict(self.core.stats), "selected": state.selected,
            "active": self.active_key, "settings": asdict(state.settings),
            "profiles": [{"key": p.key, "name": p.name, "protocol": p.protocol,
                          "source_id": p.source_id} for p in state.profiles],
            "subscriptions": [{"id": s.id, "name": s.name, "error": s.error,
                "last_success": s.last_success, "userinfo": s.userinfo,
                "count": sum(p.source_id == s.id for p in state.profiles),
                "rejected": len(s.rejected), "duplicates": s.duplicates} for s in state.subscriptions],
            "logs": list(self.core.log.lines), "latency": self.results,
            "measuring": self.measure_task is not None and not self.measure_task.done(),
            "measure_total": self.measure_total,
        }

    async def cancel_measurement(self):
        task, self.measure_task = self.measure_task, None
        if task and not task.done():
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)

    async def disconnect(self):
        await self.cancel_measurement()
        if self.connect_task and not self.connect_task.done():
            self.connect_task.cancel()
            await asyncio.gather(self.connect_task, return_exceptions=True)
        await self.core.disconnect()
        if self.core.status != Status.DISCONNECTED:
            raise UserError(self.core.error or "Не удалось завершить подключение. Повторите отключение.")
        self.active_key = None

    def connect(self):
        profile = copy.deepcopy(self.selected())
        if profile is None:
            raise UserError("Добавьте подписку или импортируйте сервер.")
        settings = copy.deepcopy(self.repo.state.settings)
        self.active_key = profile.key
        self.core.publish(Status.CONNECTING)

        async def run():
            try:
                await self.core.connect(profile, settings)
            except asyncio.CancelledError:
                raise
            except Exception as error:
                message = str(error) if isinstance(error, UserError) else "Не удалось запустить VPN. Откройте журнал."
                self.core.publish(Status.ERROR, message)
        self.connect_task = asyncio.create_task(run())

    async def dispatch(self, method, args=None):
        args = args or {}
        if not isinstance(args, dict) or not isinstance(method, str):
            raise UserError("Некорректный запрос интерфейса.")
        if self.closed and method != "shutdown":
            raise UserError("Приложение завершает работу.")
        if method == "snapshot":
            await self.core.get_stats()
            if self.connect_task and not self.connect_task.done() and self.core.status == Status.DISCONNECTED:
                self.core.publish(Status.CONNECTING)
        elif method in {"toggle", "select", "disconnect", "remove_subscription", "remove_profile"}:
            async with self.connection_lock:
                running = self.core.status in {Status.CONNECTING, Status.CONNECTED, Status.DISCONNECTING} or bool(self.connect_task and not self.connect_task.done())
                if method == "toggle":
                    if running:
                        await self.disconnect()
                    else:
                        self.connect()
                elif method == "disconnect":
                    await self.disconnect()
                elif method == "select":
                    key = str(args.get("key", ""))
                    if key != self.repo.state.selected:
                        await self.manager.select(key)
                        await self.cancel_measurement()
                        if running:
                            await self.disconnect()
                            self.connect()
                else:
                    active = next((p for p in self.repo.state.profiles if p.key == self.active_key), None)
                    removing_active = active and (active.source_id == args.get("id") if method == "remove_subscription" else active.key == args.get("key"))
                    if running and removing_active:
                        await self.disconnect()
                    if method == "remove_subscription":
                        await self.manager.remove(str(args.get("id", "")))
                    else:
                        await self.manager.remove_manual(str(args.get("key", "")))
        elif method == "import":
            value = str(args.get("text", ""))
            if len(value) > 2 * 1024 * 1024:
                raise UserError("Данные импорта слишком большие.")
            report = await self.manager.import_manual(value)
            return {"snapshot": self.snapshot(), "imported": len(report.profiles),
                    "rejected": [asdict(r) for r in report.rejected], "duplicates": report.duplicates}
        elif method == "add_subscription":
            url = str(args.get("url", "")).strip()
            if url.lower().startswith("lunaris:"):
                url = subscription_url(url)
            await self.manager.add(str(args.get("name", "")), url)
        elif method == "update_subscription":
            await self.manager.update(str(args.get("id", "")))
        elif method == "update_all":
            await self.manager.update_all()
        elif method == "settings":
            async with self.connection_lock:
                allowed = {f.name for f in fields(Settings)}
                if not args.keys() <= allowed:
                    raise UserError("Неизвестная настройка.")
                changes = dict(args)
                if self.android:
                    changes["mode"] = "tun"
                await self.manager.patch_settings(**changes)
                await self.cancel_measurement()
        elif method == "measure":
            await self.cancel_measurement()
            selected_only = args.get("selected", False)
            if self.core.status in {Status.CONNECTING, Status.DISCONNECTING}:
                raise UserError("Дождитесь завершения переключения VPN.")
            settings = copy.deepcopy(self.repo.state.settings)
            profiles = [copy.deepcopy(self.selected())] if selected_only and self.selected() else copy.deepcopy(self.repo.state.profiles)
            if "keys" in args:
                profiles = [p for p in profiles if p.key in args["keys"]]
            method_name = str(args.get("method", settings.latency_method if selected_only else "tcp"))
            if method_name not in {"tcp", "icmp", "proxy"}:
                raise UserError("Неизвестный метод измерения.")
            if self.android and method_name == "proxy" and not selected_only:
                raise UserError("На Android массовая проверка доступна через TCP/UDP и ICMP.")
            self.results = {}
            self.measure_total = len(profiles)

            async def measure():
                def result(key, value):
                    self.results[key] = {"label": value.label, "milliseconds": value.milliseconds, "error": value.error}
                if selected_only and profiles:
                    settings.latency_method = method_name
                    values = await measure_latency(profiles[0], settings, proxy_connected=self.core.status == Status.CONNECTED)
                    result(profiles[0].key, values[method_name])
                else:
                    probe = getattr(self.core, "probe_profile", None)
                    await measure_profiles(profiles, settings, method_name, proxy_probe=probe, on_result=result)
            self.measure_task = asyncio.create_task(measure())
        elif method == "cancel_measure":
            await self.cancel_measurement()
        elif method == "take_import_link":
            if self.android:
                return await self.core.bridge.take_import_link()
            from .windows_links import take_import_link
            return await asyncio.to_thread(take_import_link, self.repo.directory)
        elif method == "shutdown":
            await self.shutdown()
        else:
            raise UserError("Неизвестная команда интерфейса.")
        return self.snapshot()

    async def shutdown(self):
        if self.closed:
            return
        self.closed = True
        self.stop.set()
        if self.scheduler:
            self.scheduler.cancel()
            await asyncio.gather(self.scheduler, return_exceptions=True)
        await self.cancel_measurement()
        if not self.android:
            async with self.connection_lock:
                await self.disconnect()
