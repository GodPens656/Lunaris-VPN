"""Chaquopy entry point; the VPN service stays in its existing separate process."""
import asyncio
import json
from pathlib import Path
import threading

from .android import AndroidCore
from .engine import Engine
from .models import UserError
from .redaction import SafeLog
from .storage import AndroidVault, Repository

_loop = None
_engine = None
_initialization = None


class NativeBridge:
    def __init__(self, native):
        self.native = native

    async def call(self, method, **args):
        response = json.loads(str(await asyncio.to_thread(self.native.call, method, json.dumps(args))))
        if "error" in response:
            raise UserError(response["error"])
        return response.get("ok")

    async def connect(self, config, probe_url, *, server_name=None, verify_connection=True):
        return await self.call("connect", config=config, probe_url=probe_url,
                               server_name=server_name, verify_connection=verify_connection)

    async def disconnect(self):
        return await self.call("disconnect")

    async def snapshot(self):
        return await self.call("snapshot")

    async def vault(self, method, data):
        return await self.call(method, data=data)

    async def take_import_link(self):
        return await self.call("take_import_link")


def start(directory, native):
    global _loop, _engine, _initialization
    if _engine is not None:
        _engine.core.bridge.native = native
        return
    if _loop is None:
        _loop = asyncio.new_event_loop()
        threading.Thread(target=_loop.run_forever, name="lunaris-engine", daemon=True).start()

    async def initialize():
        global _engine
        root = Path(str(directory))
        candidates = [root / "sever", root.parent / "app_flutter" / "sever", root / "flet" / "sever"]
        storage = next((p for p in candidates if (p / "state.enc").is_file()), candidates[0])
        bridge = NativeBridge(native)
        core = AndroidCore(SafeLog(), bridge=bridge)
        repo = Repository(storage, AndroidVault(bridge))
        await repo.load()
        _engine = Engine(repo, core, android=True)
        await _engine.start()
    if _initialization is None:
        _initialization = asyncio.run_coroutine_threadsafe(initialize(), _loop)
    _initialization.result(30)


def call(method, args):
    try:
        if _engine is None:
            raise UserError("VPN-движок ещё не готов.")
        result = asyncio.run_coroutine_threadsafe(_engine.dispatch(str(method), json.loads(str(args))), _loop).result(180)
        return json.dumps({"ok": result}, ensure_ascii=True)
    except Exception as error:
        message = str(error) if isinstance(error, UserError) else "Не удалось выполнить действие. Откройте журнал."
        return json.dumps({"error": message}, ensure_ascii=True)
