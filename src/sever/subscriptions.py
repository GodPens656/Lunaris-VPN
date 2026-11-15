from __future__ import annotations

import asyncio
import base64
import binascii
import copy
import re
import uuid
from dataclasses import asdict, replace
from urllib.parse import urlsplit

import httpx

from .models import ImportReport, Profile, Settings, Subscription, UserError, timestamp
from .parser import MAX_BODY, import_local_config, parse_subscription
from .storage import Repository

TIMEOUT = 20
REDIRECT_LIMIT = 3


def validate_url(url: str) -> None:
    try:
        parsed = urlsplit(url)
        if parsed.scheme not in {"https", "http"} or not parsed.hostname or parsed.username or parsed.password or parsed.fragment:
            raise ValueError
        if parsed.port is not None and not 1 <= parsed.port <= 65535:
            raise ValueError
        if any(c.isspace() or ord(c) < 32 for c in url) or len(url) > 8192:
            raise ValueError
    except ValueError:
        raise UserError("Нужен корректный HTTP/HTTPS URL без userinfo и фрагмента. Токен может быть в пути или query.") from None


def parse_userinfo(value: str | None) -> dict[str, int]:
    if not value or len(value) > 2048:
        return {}
    result = {}
    for item in value.split(";"):
        match = re.fullmatch(r"\s*(upload|download|total|expire)\s*=\s*(\d{1,20})\s*", item)
        if match:
            result[match[1]] = int(match[2])
    return result


def parse_profile_title(value: str | None) -> str | None:
    if not value or len(value) > 2048:
        return None
    value = value.strip()
    if value.lower().startswith("base64:"):
        encoded = value[7:].strip()
        try:
            value = base64.b64decode(encoded + "=" * (-len(encoded) % 4), validate=True).decode("utf-8")
        except (ValueError, binascii.Error, UnicodeError):
            return None
    return re.sub(r"[\x00-\x1f\x7f]", " ", value).strip()[:100] or None


def replacement_selection(selected: Profile, previous: list[Profile], updated: list[Profile]) -> str | None:
    """Recover a logical server after rotating credentials or other connection fields.

    The caller supplies only profiles from the selected subscription. Require
    uniqueness in both lists so shared names/endpoints never choose an account
    by its position. Exact connection keys take precedence in update().
    """
    def endpoint(profile):
        return profile.protocol, profile.outbound["server"].casefold(), profile.outbound["server_port"]

    def name(profile):
        return profile.protocol, profile.name.strip()

    for match in (lambda p: (name(p), endpoint(p)), endpoint, name):
        identity = match(selected)
        if sum(match(p) == identity for p in previous) != 1:
            continue
        candidates = [p for p in updated if match(p) == identity]
        if len(candidates) == 1:
            return candidates[0].key
    return None


class SubscriptionFetcher:
    def __init__(self, transport=None):
        self.transport = transport

    async def fetch(self, url: str) -> tuple[bytes, dict[str, int], str | None]:
        validate_url(url)
        try:
            async with asyncio.timeout(TIMEOUT):
                async with httpx.AsyncClient(verify=True, trust_env=False, follow_redirects=False, timeout=TIMEOUT, transport=self.transport) as client:
                    original_scheme = urlsplit(url).scheme
                    for redirect in range(REDIRECT_LIMIT + 1):
                        async with client.stream("GET", url, headers={"User-Agent": "LunarisVPN/0.1", "Accept": "text/plain", "Accept-Encoding": "identity"}) as response:
                            if response.status_code in {301, 302, 303, 307, 308}:
                                if redirect == REDIRECT_LIMIT:
                                    raise UserError("Слишком много перенаправлений (максимум 3).")
                                location = response.headers.get("location")
                                if not location:
                                    raise UserError("Сервер вернул перенаправление без адреса.")
                                url = str(response.url.join(location))
                                validate_url(url)
                                if original_scheme == "https" and urlsplit(url).scheme != "https":
                                    raise UserError("Подписка перенаправляет HTTPS на HTTP. Обновление отменено.")
                                continue
                            if not 200 <= response.status_code < 300:
                                raise UserError(f"HTTP {response.status_code}. Предыдущие серверы сохранены.")
                            if "html" in response.headers.get("content-type", "").lower():
                                raise UserError("Вместо подписки получена HTML-страница.")
                            length = response.headers.get("content-length", "")
                            if length.isdigit() and int(length) > MAX_BODY:
                                raise UserError("Подписка превышает лимит 2 МиБ.")
                            body = bytearray()
                            async for chunk in response.aiter_bytes(chunk_size=16384):
                                body.extend(chunk)
                                if len(body) > MAX_BODY:
                                    raise UserError("Подписка превышает лимит 2 МиБ.")
                            return (bytes(body), parse_userinfo(response.headers.get("subscription-userinfo")),
                                parse_profile_title(response.headers.get("profile-title")))
        except UserError:
            raise
        except (TimeoutError, httpx.TimeoutException):
            raise UserError("Истекло время запроса подписки (20 секунд).") from None
        except (httpx.HTTPError, ValueError):
            raise UserError("Не удалось загрузить подписку. Проверьте сеть, URL и TLS-сертификат.") from None
        raise UserError("Не удалось получить подписку.")


class SubscriptionManager:
    def __init__(self, repository: Repository, fetcher: SubscriptionFetcher | None = None):
        self.repo = repository
        self.fetcher = fetcher or SubscriptionFetcher()
        self._updating: dict[str, asyncio.Lock] = {}
        self.changed = asyncio.Event()

    async def add(self, name: str, url: str) -> str:
        url = url.strip()
        validate_url(url)
        name = name.strip()[:100]
        item = Subscription(str(uuid.uuid4()), name or urlsplit(url).hostname, url, auto_name=not name)
        async with self.repo.lock:
            state = copy.deepcopy(self.repo.state)
            state.subscriptions.append(item)
            await self.repo.commit(state)
        self.changed.set()
        await self.update(item.id)
        return item.id

    async def update(self, source_id: str) -> ImportReport:
        async with self._updating.setdefault(source_id, asyncio.Lock()):
            item = next((s for s in self.repo.state.subscriptions if s.id == source_id), None)
            if item is None:
                raise UserError("Подписка уже удалена.")
            report = None
            try:
                body, userinfo, title = await self.fetcher.fetch(item.url)
                report = await asyncio.to_thread(parse_subscription, body, source_id)
                if not report.profiles:
                    raise UserError("В обновлении нет валидных серверов. Предыдущие серверы сохранены.")
                async with self.repo.lock:
                    state = copy.deepcopy(self.repo.state)
                    target = next((s for s in state.subscriptions if s.id == source_id), None)
                    if target is None:
                        raise UserError("Подписка удалена во время обновления.")
                    previous = [p for p in state.profiles if p.source_id == source_id]
                    selected = next((p for p in previous if p.key == state.selected), None)
                    state.profiles = [p for p in state.profiles if p.source_id != source_id] + report.profiles
                    if state.selected not in {p.key for p in state.profiles}:
                        replacement = replacement_selection(selected, previous, report.profiles) if selected else None
                        state.selected = replacement or (state.profiles[0].key if state.profiles else None)
                    target.last_success, target.error, target.userinfo = timestamp(), None, userinfo
                    if target.auto_name and title:
                        target.name = title
                    target.rejected = [asdict(r) for r in report.rejected]
                    target.duplicates = report.duplicates
                    await self.repo.commit(state)
                return report
            except UserError as error:
                async with self.repo.lock:
                    state = copy.deepcopy(self.repo.state)
                    target = next((s for s in state.subscriptions if s.id == source_id), None)
                    if target is not None:
                        target.error = str(error)
                        if report is not None:
                            target.rejected = [asdict(r) for r in report.rejected]
                            target.duplicates = report.duplicates
                        await self.repo.commit(state)
                raise
            finally:
                self.changed.set()

    async def update_all(self) -> list[str]:
        errors = []
        # Bounded sequential requests prevent a large collection from flooding the network.
        for source in list(self.repo.state.subscriptions):
            try:
                await self.update(source.id)
            except UserError as error:
                errors.append(str(error))
        return errors

    async def remove(self, source_id: str) -> None:
        async with self.repo.lock:
            state = copy.deepcopy(self.repo.state)
            state.subscriptions = [s for s in state.subscriptions if s.id != source_id]
            state.profiles = [p for p in state.profiles if p.source_id != source_id]
            if state.selected not in {p.key for p in state.profiles}:
                state.selected = state.profiles[0].key if state.profiles else None
            await self.repo.commit(state)
        self.changed.set()

    async def import_manual(self, text: str) -> ImportReport:
        report = await asyncio.to_thread(import_local_config if text.strip().startswith("{") else parse_subscription, text)
        if not report.profiles:
            reason = report.rejected[0].reason if report.rejected else "Нет валидных серверов."
            raise UserError(reason)
        async with self.repo.lock:
            state = copy.deepcopy(self.repo.state)
            existing = {p.identity for p in state.profiles if p.source_id is None}
            for profile in report.profiles:
                if profile.identity not in existing:
                    state.profiles.append(profile)
                    existing.add(profile.identity)
                else:
                    report.duplicates += 1
            if state.selected is None and state.profiles:
                state.selected = state.profiles[0].key
            await self.repo.commit(state)
        self.changed.set()
        return report

    async def select(self, key: str) -> None:
        async with self.repo.lock:
            state = copy.deepcopy(self.repo.state)
            if key not in {p.key for p in state.profiles}:
                raise UserError("Этот сервер уже удалён.")
            state.selected = key
            await self.repo.commit(state)
        self.changed.set()

    async def remove_manual(self, key: str) -> None:
        async with self.repo.lock:
            state = copy.deepcopy(self.repo.state)
            state.profiles = [p for p in state.profiles if p.key != key or p.source_id is not None]
            if state.selected not in {p.key for p in state.profiles}:
                state.selected = state.profiles[0].key if state.profiles else None
            await self.repo.commit(state)
        self.changed.set()

    async def save_settings(self, settings: Settings) -> None:
        settings.validate()
        async with self.repo.lock:
            state = copy.deepcopy(self.repo.state)
            state.settings = settings
            await self.repo.commit(state)
        self.changed.set()

    async def patch_settings(self, **changes) -> None:
        """Validate and persist changed fields without replacing concurrent updates."""
        async with self.repo.lock:
            state = copy.deepcopy(self.repo.state)
            state.settings = replace(state.settings, **changes)
            state.settings.validate()
            await self.repo.commit(state)
        self.changed.set()

    async def save_connection_mode(self, mode: str) -> None:
        """Persist only the mode, preserving changes from concurrent updates."""
        async with self.repo.lock:
            state = copy.deepcopy(self.repo.state)
            state.settings.mode = mode
            state.settings.validate()
            await self.repo.commit(state)
        self.changed.set()

    async def save_core(self, core: str) -> None:
        """Persist the selected engine without replacing other saved settings."""
        async with self.repo.lock:
            state = copy.deepcopy(self.repo.state)
            state.settings.core = core
            state.settings.validate()
            await self.repo.commit(state)
        self.changed.set()

    async def scheduler(self, stop: asyncio.Event) -> None:
        if self.repo.state.settings.update_on_start:
            await self.update_all()
        last = timestamp()
        while not stop.is_set():
            try:
                await asyncio.wait_for(stop.wait(), 5)
            except TimeoutError:
                pass
            interval = self.repo.state.settings.update_minutes
            if interval and timestamp() - last >= interval * 60 and not stop.is_set():
                await self.update_all()
                last = timestamp()
