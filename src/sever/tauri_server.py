"""Private newline JSON RPC over inherited pipes, never a listening TCP server."""
import asyncio
import json
import os
from pathlib import Path
import sys

from .engine import Engine
from .models import UserError
from .redaction import SafeLog
from .storage import Repository, WindowsVault, data_directory


async def serve():
    from .windows import WindowsCore
    from .windows_native import SingleInstance
    from .windows_links import register_protocol
    isolated = os.environ.get("LUNARIS_DATA_DIR")
    directory = Path(isolated) if isolated else data_directory()
    directory.mkdir(parents=True, exist_ok=True)
    mutex_name = "Local\\SeverVPN"
    if isolated:
        import hashlib
        mutex_name += "-" + hashlib.sha256(str(directory.resolve()).encode()).hexdigest()[:16]
    mutex = SingleInstance(mutex_name)
    log = SafeLog()
    core = WindowsCore(directory / "runtime", log)
    await core.recover()
    repo = Repository(directory, WindowsVault(directory), default_core="mihomo")
    await repo.load()
    engine = Engine(repo, core)
    await engine.start()
    if os.environ.get("LUNARIS_LAUNCHER") and not isolated:
        try:
            await asyncio.to_thread(register_protocol, directory)
        except OSError:
            log.add("Не удалось зарегистрировать ссылки lunaris://.")
    try:
        while line := await asyncio.to_thread(sys.stdin.buffer.readline, 3 * 1024 * 1024):
            try:
                request = json.loads(line)
                result = await engine.dispatch(request.get("method"), request.get("args"))
                response = {"ok": result}
            except Exception as error:
                message = str(error) if isinstance(error, UserError) else "Не удалось выполнить действие. Проверьте настройки и журнал."
                log.add(message)
                response = {"error": message}
            sys.stdout.write(json.dumps(response, ensure_ascii=True, separators=(",", ":")) + "\n")
            sys.stdout.flush()
            if engine.closed:
                break
    finally:
        await engine.shutdown()
        mutex.close()


def run():
    if sys.platform != "win32":
        raise SystemExit("The desktop engine requires Windows")
    asyncio.run(serve())


if __name__ == "__main__":
    run()
