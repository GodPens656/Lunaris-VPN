from __future__ import annotations

import hashlib
import json
import time
from dataclasses import asdict, dataclass, field
from enum import StrEnum
from typing import Any


class UserError(Exception):
    """Only constant, safe-to-display messages may be passed to this exception."""


class Status(StrEnum):
    DISCONNECTED = "disconnected"
    CONNECTING = "connecting"
    CONNECTED = "connected"
    DISCONNECTING = "disconnecting"
    ERROR = "error"


@dataclass
class Profile:
    name: str
    outbound: dict[str, Any]
    source_id: str | None = None
    # Settings/hints which have no equivalent in sing-box (e.g. encryption, QUIC fp).
    options: dict[str, Any] = field(default_factory=dict)

    @property
    def identity(self) -> str:
        connection = {k: v for k, v in self.outbound.items() if k != "tag"}
        if self.options:
            connection = {**connection, "share_options": self.options}
        canonical = json.dumps(connection, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
        return hashlib.sha256(canonical.encode()).hexdigest()

    @property
    def key(self) -> str:
        return f"{self.source_id or 'manual'}:{self.identity}"

    @property
    def protocol(self) -> str:
        return self.outbound["type"]

    @property
    def requires_xray(self) -> bool:
        return self.protocol in {"vless", "trojan"} and (
            self.outbound.get("transport", {}).get("type") == "xhttp"
            or self.requires_xray_grpc
            or "spx" in self.options or "support-x25519mlkem768" in self.options
            or self.options.get("encryption", "none") != "none"
        )

    @property
    def requires_xray_grpc(self) -> bool:
        return self.outbound.get("transport", {}).get("type") == "grpc" and (
            self.options.get("grpc_mode") == "multi" or bool(self.options.get("grpc_authority"))
        )


@dataclass
class Rejection:
    line: int
    reason: str


@dataclass
class ImportReport:
    profiles: list[Profile] = field(default_factory=list)
    rejected: list[Rejection] = field(default_factory=list)
    duplicates: int = 0


@dataclass
class Subscription:
    id: str
    name: str
    url: str
    last_success: float | None = None
    error: str | None = None
    userinfo: dict[str, int] = field(default_factory=dict)
    rejected: list[dict] = field(default_factory=list)
    duplicates: int = 0
    auto_name: bool = False


@dataclass
class Settings:
    mode: str = "proxy"
    mixed_port: int = 2080
    api_port: int = 2081
    dns_server: str = "1.1.1.1"
    dns_tls_name: str = "cloudflare-dns.com"
    dns_kind: str = "https"
    bootstrap_dns: str = "1.1.1.1"
    ipv6: bool = True
    update_on_start: bool = True
    update_minutes: int = 360
    probe_url: str = "https://www.gstatic.com/generate_204"
    verify_connection: bool = True
    latency_method: str = "proxy"
    auto_sort_ping: bool = True
    minimize_to_tray: bool = True
    close_to_tray: bool = True
    core_path: str = ""
    core: str = "sing-box"
    mihomo_path: str = ""
    bypass_russian_domains: bool = False

    def validate(self) -> None:
        import ipaddress
        from urllib.parse import urlsplit

        if self.core not in {"sing-box", "mihomo"}:
            raise UserError("Неизвестное ядро подключения.")
        if self.mode not in {"proxy", "tun"}:
            raise UserError("Неизвестный режим подключения.")
        if self.latency_method not in {"tcp", "icmp", "proxy"}:
            raise UserError("Выберите PROXY GET, TCP/UDP или ICMP для измерения задержки.")
        if type(self.bypass_russian_domains) is not bool:
            raise UserError("Для обхода VPN доменами .рф, .su и .ru нужно логическое значение.")
        if type(self.verify_connection) is not bool:
            raise UserError("Для HTTPS-проверки при подключении нужно логическое значение.")
        if not all(type(p) is int and 1024 <= p <= 65535 for p in [self.mixed_port, self.api_port]):
            raise UserError("Локальные порты должны быть в диапазоне 1024–65535.")
        if self.mixed_port == self.api_port:
            raise UserError("Порты прокси и управления должны различаться.")
        try:
            ipaddress.ip_address(self.dns_server)
            ipaddress.ip_address(self.bootstrap_dns)
        except ValueError:
            raise UserError("Для DNS нужен IP-адрес, чтобы избежать циклического разрешения.") from None
        if self.dns_kind not in {"https", "tls", "udp"}:
            raise UserError("Выберите HTTPS, TLS или UDP DNS.")
        if self.dns_kind != "udp" and (not self.dns_tls_name or any(c in self.dns_tls_name for c in "/\r\n :")):
            raise UserError("Введите корректное TLS-имя DNS-сервера.")
        if type(self.update_minutes) is not int or not 0 <= self.update_minutes <= 10080:
            raise UserError("Интервал обновления: 0 (выключено) или 1–10080 минут.")
        try:
            probe = urlsplit(self.probe_url)
            if probe.scheme != "https" or not probe.hostname or probe.username:
                raise ValueError
        except ValueError:
            raise UserError("Адрес проверки соединения должен быть HTTPS URL без учётных данных.") from None


@dataclass
class Stats:
    upload: int = 0
    download: int = 0
    duration: int = 0


@dataclass
class State:
    profiles: list[Profile] = field(default_factory=list)
    subscriptions: list[Subscription] = field(default_factory=list)
    selected: str | None = None
    settings: Settings = field(default_factory=Settings)

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, value: dict, *, default_core: str = "sing-box") -> State:
        return cls(
            profiles=[Profile(**p) for p in value.get("profiles", [])],
            subscriptions=[Subscription(**s) for s in value.get("subscriptions", [])],
            selected=value.get("selected"),
            settings=Settings(**{"core": default_core, **value.get("settings", {})}),
        )


def timestamp() -> float:
    return time.time()
