"""Conservative URI parser. Unknown or inapplicable fields are rejected, never dropped."""
from __future__ import annotations

import base64
import binascii
import ipaddress
import json
import re
import uuid
from urllib.parse import unquote, urlsplit

from .models import ImportReport, Profile, Rejection, UserError

MAX_BODY = 2 * 1024 * 1024
MAX_LINES = 10000
MAX_URI = 16384
FINGERPRINTS = {"chrome", "firefox", "edge", "safari", "360", "qq", "ios", "android", "random", "randomized"}
TLS_KEYS = {"sni", "peer", "alpn", "fp", "allowInsecure", "insecure", "ech"}
TRANSPORT_KEYS = {"type", "path", "host", "serviceName", "authority", "mode", "headerType", "ed", "eh", "extra", "x_padding_bytes"}
REALITY_KEYS = {"pbk", "sid", "spx", "support-x25519mlkem768"}


def normalize_share_uri(uri: str) -> str:
    """Accept the explicit Markdown escaping produced when copying a share link."""
    if re.match(r"(?i)^(vless|trojan|hysteria2|hy2)\\://", uri) or "(mailto:" in uri:
        uri = re.sub(r"\[([^\[\]]+)\]\(mailto:[^()]*\)", r"\1", uri)
        uri = re.sub(r"\\([:._])", r"\1", uri)
        uri = re.sub(r"\s*&#(?:x20|32);\s*$", "", uri).strip()
        uri = uri.rstrip("\\")
    return uri


def ech_options(value: str) -> dict:
    try:
        raw = base64.b64decode(value, validate=True)
        # ECHConfigList has a two-byte length prefix and one or more opaque configs.
        if len(raw) < 6 or int.from_bytes(raw[:2], "big") != len(raw) - 2:
            raise ValueError
        offset = 2
        while offset < len(raw):
            size = int.from_bytes(raw[offset + 2:offset + 4], "big")
            if size == 0 or offset + 4 + size > len(raw):
                raise ValueError
            offset += 4 + size
        if offset != len(raw):
            raise ValueError
    except (ValueError, binascii.Error):
        raise UserError("ECH должен содержать корректный Base64 ECHConfigList.") from None
    encoded = base64.b64encode(raw).decode("ascii")
    pem = "-----BEGIN ECH CONFIGS-----\n" + "\n".join(encoded[i:i + 64] for i in range(0, len(encoded), 64)) + "\n-----END ECH CONFIGS-----"
    return {"enabled": True, "config": [pem]}


def xhttp_options(q: dict) -> dict:
    if {"serviceName", "authority", "headerType", "ed", "eh"}.intersection(q):
        raise UserError("Параметры другого транспорта заданы для XHTTP.")
    try:
        extra = json.loads(q.get("extra", "{}"), object_pairs_hook=unique_json_object)
        if not isinstance(extra, dict):
            raise ValueError
    except (ValueError, TypeError, RecursionError):
        raise UserError("XHTTP extra должен быть JSON-объектом без повторяющихся полей.") from None
    if set(extra) - {"mode", "xPaddingBytes"}:
        raise UserError("XHTTP extra поддерживает mode и xPaddingBytes; другие поля пока не поддерживаются.")
    for uri_key, json_key in [("mode", "mode"), ("x_padding_bytes", "xPaddingBytes")]:
        if uri_key in q:
            if json_key in extra and extra[json_key] != q[uri_key]:
                raise UserError("Параметры XHTTP в ссылке и extra противоречат друг другу.")
            extra[json_key] = q[uri_key]
    mode = extra.pop("mode", "auto")
    if not isinstance(mode, str) or mode not in {"auto", "packet-up", "stream-up", "stream-one"}:
        raise UserError("Неподдерживаемый режим XHTTP.")
    padding = extra.get("xPaddingBytes")
    if padding is not None:
        if not isinstance(padding, str) or not re.fullmatch(r"[0-9]{1,5}(?:-[0-9]{1,5})?", padding):
            raise UserError("Некорректный диапазон xPaddingBytes.")
        values = [int(v) for v in padding.split("-")]
        if not (padding == "0" or 1 <= values[0] <= values[-1] <= 65536):
            raise UserError("Некорректный диапазон xPaddingBytes.")
    path = q.get("path", "/")
    if not path.startswith("/"):
        raise UserError("Путь транспорта должен начинаться с /.")
    result = {"type": "xhttp", "path": path, "host": q.get("host", ""), "mode": mode}
    if extra:
        result["extra"] = extra
    return result


def unique_json_object(pairs: list) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError
        result[key] = value
    return result


def decode(value: str) -> str:
    if re.search(r"%(?![0-9a-fA-F]{2})", value):
        raise UserError("Некорректный percent-encoding.")
    try:
        result = unquote(value, encoding="utf-8", errors="strict")
    except UnicodeError:
        raise UserError("Некорректная UTF-8 строка.") from None
    if any(ord(c) < 32 or ord(c) == 127 for c in result):
        raise UserError("Управляющие символы в ссылке запрещены.")
    return result


def boolean(value: str) -> bool:
    if value not in {"0", "1", "true", "false"}:
        raise UserError("Булевый параметр должен быть 0/1 или true/false.")
    return value in {"1", "true"}


def vless_encryption(value: str) -> str:
    """Validate Xray's VLESS Encryption string without exposing its keys."""
    if value == "none":
        return value
    parts = value.split(".")
    error = "Некорректный VLESS encryption: ожидается mlkem768x25519plus, режим native/xorpub/random, 0rtt/1rtt и ключ сервера."
    if (len(parts) < 4 or parts[0] != "mlkem768x25519plus"
            or parts[1] not in {"native", "xorpub", "random"}
            or parts[2] not in {"0rtt", "1rtt"}):
        raise UserError(error)
    keys_started = False
    padding_length = 0
    for index, part in enumerate(parts[3:]):
        if not keys_started and re.fullmatch(r"[0-9]{1,5}-[0-9]{1,5}-[0-9]{1,5}", part):
            probability, minimum, maximum = map(int, part.split("-"))
            if not (0 <= probability <= 100 and 0 <= minimum <= maximum <= 65553):
                raise UserError("Некорректный padding VLESS encryption.")
            if index == 0 and (probability != 100 or minimum < 35):
                raise UserError("Первый padding VLESS encryption требует вероятность 100 и длину от 35 байт.")
            if index % 2 == 0:
                padding_length += maximum
                if padding_length > 65553:
                    raise UserError("Суммарный padding VLESS encryption превышает 65553 байта.")
            continue
        keys_started = True
        try:
            if len(part) not in {43, 1579} or not re.fullmatch(r"[A-Za-z0-9_-]+", part):
                raise ValueError
            raw = base64.b64decode(part + "=" * (-len(part) % 4), altchars=b"-_", validate=True)
            if len(raw) not in {32, 1184}:
                raise ValueError
        except (ValueError, binascii.Error):
            raise UserError(error) from None
    if not keys_started:
        raise UserError(error)
    return value


def host(value: str) -> str:
    value = decode(value).strip()
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        try:
            result = value.rstrip(".").encode("idna").decode("ascii").lower()
        except UnicodeError:
            raise UserError("Некорректный адрес сервера.") from None
        if len(result) > 253 or not result or any(not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", p) for p in result.split(".")):
            raise UserError("Некорректный адрес сервера.")
        return result


def alias(q: dict, first: str, second: str, default: str = "") -> str:
    if first in q and second in q:
        raise UserError("Одновременно заданы дублирующие параметры.")
    return q.get(first, q.get(second, default))


def tls_options(q: dict, server: str, security: str) -> dict | None:
    if security == "none":
        if TLS_KEYS.intersection(q) or REALITY_KEYS.intersection(q):
            raise UserError("TLS-параметры заданы при отключённом TLS.")
        return None
    if security not in {"tls", "reality"}:
        raise UserError("Этот тип безопасности не поддерживается sing-box 1.14.0.")
    tls = {"enabled": True, "server_name": host(alias(q, "sni", "peer", server))}
    insecure = alias(q, "insecure", "allowInsecure", "0")
    if boolean(insecure):
        tls["insecure"] = True
    if "alpn" in q:
        alpn = q["alpn"].split(",")
        if any(not p or len(p.encode()) > 255 for p in alpn):
            raise UserError("Некорректный ALPN.")
        tls["alpn"] = alpn
    if "ech" in q:
        if security != "tls":
            raise UserError("ECH поддерживается только с security=tls.")
        tls["ech"] = ech_options(q["ech"])
    if "fp" in q or security == "reality":
        fp = q.get("fp", "chrome")
        if fp not in FINGERPRINTS:
            raise UserError("TLS fingerprint не поддерживается выбранным ядром.")
        tls["utls"] = {"enabled": True, "fingerprint": fp}
    if security == "reality":
        if "sni" not in q or not q.get("pbk"):
            raise UserError("Reality требует SNI и public key (pbk).")
        try:
            if not re.fullmatch(r"[A-Za-z0-9_-]{43}", q["pbk"]) or len(base64.urlsafe_b64decode(q["pbk"] + "=")) != 32:
                raise ValueError
        except (ValueError, binascii.Error):
            raise UserError("Reality public key должен быть 32-байтовым Base64URL ключом.") from None
        sid = q.get("sid", "").lower()
        if len(sid) > 16 or len(sid) % 2 or not re.fullmatch(r"[0-9a-f]*", sid):
            raise UserError("Reality short ID должен содержать до 16 hex-символов чётной длины.")
        tls["reality"] = {"enabled": True, "public_key": q["pbk"], "short_id": sid}
    elif REALITY_KEYS.intersection(q):
        raise UserError("Reality-параметры заданы без security=reality.")
    return tls


def transport_options(q: dict) -> dict | None:
    kind = q.get("type", "tcp")
    if kind == "xhttp":
        return xhttp_options(q)
    if kind in {"tcp", "raw", "original"}:
        if any(k in q for k in TRANSPORT_KEYS - {"type", "headerType"}) or q.get("headerType", "none") != "none":
            raise UserError("Параметры транспорта несовместимы с обычным TCP; HTTP camouflage не поддерживается.")
        return None
    if kind not in {"ws", "grpc", "http", "h2", "httpupgrade"}:
        raise UserError("Транспорт не поддерживается: доступны TCP, WS, HTTP, gRPC, HTTPUpgrade и XHTTP.")
    if {"extra", "x_padding_bytes"}.intersection(q):
        raise UserError("XHTTP-параметры заданы для другого транспорта.")
    if "headerType" in q:
        raise UserError("headerType не поддерживается для этого транспорта.")
    if kind == "grpc":
        if {"path", "host", "ed", "eh"}.intersection(q):
            raise UserError("HTTP/WS-параметры несовместимы с gRPC; используйте serviceName и authority.")
        if q.get("mode", "gun") not in {"", "gun", "multi"}:
            raise UserError("Для gRPC доступны mode=gun и mode=multi.")
        authority = q.get("authority", "")
        if authority:
            try:
                parsed = urlsplit("//" + authority)
                if (not parsed.hostname or parsed.username is not None or parsed.password is not None
                        or parsed.path or parsed.query or parsed.fragment or any(c.isspace() for c in authority)
                        or not authority.isascii() or authority.endswith(":")):
                    raise ValueError
                host(parsed.hostname)
                if parsed.port is not None and not 1 <= parsed.port <= 65535:
                    raise ValueError
            except (ValueError, UserError):
                raise UserError("gRPC authority должен содержать домен или IP с необязательным портом.") from None
        return {"type": "grpc", "service_name": q.get("serviceName", "")}
    if {"serviceName", "authority", "mode"}.intersection(q):
        raise UserError("gRPC-параметры заданы для другого транспорта.")
    path = q.get("path", "/")
    if not path.startswith("/"):
        raise UserError("Путь транспорта должен начинаться с /.")
    result = {"type": "http" if kind == "h2" else kind, "path": path}
    if "host" in q:
        if kind == "ws":
            result["headers"] = {"Host": q["host"]}
        else:
            result["host"] = q["host"].split(",") if result["type"] == "http" else q["host"]
    if {"ed", "eh"}.intersection(q):
        if kind != "ws":
            raise UserError("Early data поддерживается только для WebSocket.")
        try:
            ed = int(q.get("ed", "0"))
            if not 0 <= ed <= 65536:
                raise ValueError
        except ValueError:
            raise UserError("Некорректный размер WebSocket early data.") from None
        result["max_early_data"] = ed
        result["early_data_header_name"] = q.get("eh", "Sec-WebSocket-Protocol")
    return result


def parse_uri(uri: str, source_id: str | None = None) -> Profile:
    uri = normalize_share_uri(uri)
    if len(uri) > MAX_URI:
        raise UserError("Ссылка слишком длинная.")
    if any(ord(c) < 32 or c.isspace() for c in uri):
        raise UserError("Пробелы и управляющие символы должны быть percent-encoded.")
    try:
        parsed = urlsplit(uri)
        scheme = parsed.scheme.lower()
        if scheme == "hy2":
            scheme = "hysteria2"
        if scheme not in {"vless", "trojan", "hysteria2"}:
            names = {"vmess": "VMess", "ss": "Shadowsocks", "ssr": "ShadowsocksR", "tuic": "TUIC",
                     "wireguard": "WireGuard", "wg": "WireGuard", "anytls": "AnyTLS", "socks": "SOCKS",
                     "socks5": "SOCKS5", "http": "HTTP", "https": "HTTPS"}
            if scheme in names:
                raise UserError(f"Протокол {names[scheme]} ({scheme}://) пока не поддерживается импортёром. Это не ошибка транспорта gRPC.")
            if not scheme:
                raise UserError("Не распознан формат ссылки. Ожидается URI, начинающийся с vless://, trojan://, hysteria2:// или hy2://.")
            raise UserError("Неизвестный протокол ссылки. Поддерживаются vless://, trojan://, hysteria2:// и hy2://.")
        if not parsed.hostname or "@" not in parsed.netloc:
            raise UserError("Не указан адрес сервера или учётные данные.")
        server = host(parsed.hostname)
        port = parsed.port
        if port is None:
            if scheme == "vless":
                raise UserError("Для VLESS нужно указать порт.")
            port = 443
        if not 1 <= port <= 65535:
            raise UserError("Порт сервера должен быть в диапазоне 1–65535.")
        auth = decode(parsed.netloc.rsplit("@", 1)[0])
        if not auth:
            raise UserError("Учётные данные не могут быть пустыми.")
        if parsed.path not in {"", "/"}:
            raise UserError("Путь URI не поддерживается; используйте параметр path для транспорта.")
    except ValueError:
        raise UserError("Некорректный URI, IPv6 или порт; hopping-порты пока не поддерживаются.") from None
    q = {}
    for item in parsed.query.split("&") if parsed.query else []:
        k, sep, v = item.partition("=")
        k, v = decode(k), decode(v)
        if not sep or not k or k in q:
            raise UserError("Некорректный или повторяющийся query-параметр.")
        q[k] = v
    allowed = TLS_KEYS | TRANSPORT_KEYS | {"security"}
    if scheme == "vless":
        allowed |= {"encryption", "flow", "packetEncoding"} | REALITY_KEYS
    elif scheme == "trojan":
        allowed |= REALITY_KEYS
    elif scheme == "hysteria2":
        allowed = TLS_KEYS | {"security", "obfs", "obfs-password"}
    unknown = set(q) - allowed
    if unknown:
        safe_key = sorted(unknown)[0]
        known_unsupported = {"pqv", "spx", "pinSHA256", "ech", "mport", "upmbps", "downmbps", "plugin", "encryption"}
        if safe_key in known_unsupported:
            raise UserError(f"Параметр {safe_key} не поддерживается текущим импортёром; профиль отклонён.")
        raise UserError("Неизвестный query-параметр; профиль отклонён без изменения его смысла.")
    outbound = {"type": scheme, "server": server, "server_port": port}
    options = {}
    if scheme == "vless":
        try:
            outbound["uuid"] = str(uuid.UUID(auth))
        except ValueError:
            raise UserError("Некорректный UUID VLESS.") from None
        encryption = vless_encryption(q.get("encryption", "none"))
        if encryption != "none":
            options["encryption"] = encryption
        flow = q.get("flow", "")
        if flow not in {"", "xtls-rprx-vision"}:
            raise UserError("Поддерживается только flow=xtls-rprx-vision.")
        if flow:
            if encryption == "none" and (q.get("security", "none") == "none" or q.get("type", "tcp") not in {"tcp", "raw", "original"}):
                raise UserError("Vision требует VLESS encryption либо TLS/Reality с обычным TCP.")
            outbound["flow"] = flow
        if "packetEncoding" in q:
            if q["packetEncoding"] not in {"xudp", "packetaddr"}:
                raise UserError("Неподдерживаемый packetEncoding.")
            outbound["packet_encoding"] = q["packetEncoding"]
    else:
        outbound["password"] = auth
    if scheme == "hysteria2":
        if q.get("security", "tls") != "tls":
            raise UserError("Hysteria2 требует security=tls.")
        # Hysteria2 uses QUIC TLS, which cannot use uTLS browser fingerprints.
        tls = tls_options(q, server, "tls")
        tls.pop("utls", None)
        if "fp" in q:
            options["fp"] = q["fp"]
        if "obfs" in q:
            if q["obfs"] != "salamander" or not q.get("obfs-password"):
                raise UserError("Поддерживается obfs=salamander с непустым obfs-password; gecko пока не поддерживается.")
            outbound["obfs"] = {"type": "salamander", "password": q["obfs-password"]}
        elif "obfs-password" in q:
            raise UserError("obfs-password указан без obfs.")
    else:
        security = q.get("security", "none" if scheme == "vless" else "tls")
        if scheme == "trojan" and security not in {"tls", "reality"}:
            raise UserError("Trojan требует TLS или Reality.")
        tls = tls_options(q, server, security)
        transport = transport_options(q)
        if scheme == "trojan" and q.get("type") == "xhttp":
            raise UserError("XHTTP поддерживается только для VLESS.")
        if transport:
            outbound["transport"] = transport
            if transport["type"] == "grpc":
                if tls and "alpn" in tls and "h2" not in tls["alpn"]:
                    raise UserError("gRPC требует HTTP/2: ALPN должен включать h2.")
                if q.get("mode") == "multi":
                    options["grpc_mode"] = "multi"
                if q.get("authority"):
                    options["grpc_authority"] = q["authority"]
        if "spx" in q:
            if not q["spx"].startswith("/"):
                raise UserError("Reality spiderX должен начинаться с /.")
            options["spx"] = q["spx"]
        if "support-x25519mlkem768" in q:
            options["support-x25519mlkem768"] = boolean(q["support-x25519mlkem768"])
    if tls:
        outbound["tls"] = tls
    name = decode(parsed.fragment) if parsed.fragment else f"{scheme.upper()} · {server}"
    profile = Profile(name[:180], outbound, source_id, options)
    if profile.requires_xray:
        # Fail unsupported combinations during import, before users select them.
        from .xray import build_xray_config
        build_xray_config(profile, 1080, "validation")
    return profile


def parse_subscription(body: bytes | str, source_id: str | None = None) -> ImportReport:
    if isinstance(body, str):
        body = body.encode("utf-8")
    if len(body) > MAX_BODY:
        raise UserError("Подписка превышает лимит 2 МиБ.")
    try:
        text = body.decode("utf-8-sig").strip()
    except UnicodeError:
        raise UserError("Подписка не является UTF-8 текстом.") from None
    if not text:
        raise UserError("Подписка пуста. Предыдущие серверы сохранены.")
    if text.lstrip().startswith(("<", "{", "[")) or re.match(r"(?i)(proxies|proxy-groups|mixed-port):", text):
        raise UserError("HTML, Clash YAML и удалённый sing-box JSON не поддерживаются. Ожидается список URI или Base64.")
    if "://" not in text and "\\://" not in text:
        compact = "".join(text.split())
        try:
            text = base64.b64decode(compact + "=" * (-len(compact) % 4), altchars=b"-_", validate=True).decode("utf-8-sig").strip()
        except (binascii.Error, UnicodeError, ValueError):
            raise UserError("Ответ не является списком ссылок или корректным Base64.") from None
    lines = text.splitlines()
    if len(lines) > MAX_LINES:
        raise UserError("Подписка содержит больше 10000 строк.")
    report, seen = ImportReport(), set()
    for index, line in enumerate(lines, 1):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        try:
            profile = parse_uri(line, source_id)
            if profile.identity in seen:
                report.duplicates += 1
            else:
                seen.add(profile.identity)
                report.profiles.append(profile)
        except UserError as error:
            report.rejected.append(Rejection(index, str(error)))
    return report


def import_local_config(text: str) -> ImportReport:
    """Only a list of share URIs under a versioned schema; never execute arbitrary JSON."""
    if len(text.encode()) > MAX_BODY:
        raise UserError("Конфигурация превышает лимит 2 МиБ.")
    try:
        value = json.loads(text)
        if set(value) != {"version", "links"} or value["version"] != 1 or not isinstance(value["links"], list):
            raise ValueError
        if not all(isinstance(link, str) and "\n" not in link for link in value["links"]):
            raise ValueError
    except (ValueError, TypeError, AttributeError):
        raise UserError('Локальный JSON должен иметь формат {"version":1,"links":["vless://…"]}. Полный sing-box JSON не импортируется.') from None
    return parse_subscription("\n".join(value["links"]))
