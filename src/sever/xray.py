"""Translate validated VLESS/Trojan profiles into an isolated Xray SOCKS sidecar."""
from copy import deepcopy

from .models import Profile, Settings, UserError

XRAY_VERSION = "26.3.27"


def xray_ech_config(ech: dict) -> str:
    """Convert the validated sing-box PEM wrapper to Xray's ECHConfigList."""
    if not isinstance(ech, dict):
        raise UserError("Некорректный ECHConfigList в профиле Xray.")
    configs = ech.get("config", [])
    if ech.get("enabled") is not True or not isinstance(configs, list) or len(configs) != 1 or not isinstance(configs[0], str):
        raise UserError("Xray требует один включённый ECHConfigList для этого профиля.")
    lines = configs[0].splitlines()
    if len(lines) < 3 or lines[0] != "-----BEGIN ECH CONFIGS-----" or lines[-1] != "-----END ECH CONFIGS-----":
        raise UserError("Некорректный формат ECHConfigList в профиле Xray.")
    encoded = "".join(lines[1:-1])
    # Also validate saved profiles, which can reach the builder without URI import.
    from .parser import ech_options
    ech_options(encoded)
    return encoded


def build_xray_config(profile: Profile, port: int, password: str, settings: Settings | None = None, *, endpoint_hosts: dict | None = None) -> dict:
    if not profile.requires_xray:
        raise UserError("Этот профиль не требует Xray.")
    outbound = profile.outbound
    settings = settings or Settings()
    settings.validate()
    tls = outbound.get("tls", {})
    transport = deepcopy(outbound.get("transport", {"type": "tcp"}))
    kind = transport.pop("type")
    if kind not in {"tcp", "xhttp", "ws", "grpc", "httpupgrade"}:
        raise UserError("Мост Xray поддерживает TCP, XHTTP, WS, gRPC и HTTPUpgrade.")
    stream = {"network": "raw" if kind == "tcp" else kind,
              "security": "reality" if "reality" in tls else "tls" if tls else "none",
              "sockopt": {"domainStrategy": "UseIP" if settings.ipv6 else "UseIPv4"}}
    if kind == "xhttp":
        stream["xhttpSettings"] = transport
    elif kind == "ws":
        if transport.get("max_early_data", 0):
            raise UserError("WebSocket early data через мост Xray пока не поддерживается.")
        stream["wsSettings"] = {"path": transport.get("path", "/"),
                                "headers": transport.get("headers", {})}
    elif kind == "grpc":
        stream["grpcSettings"] = {"serviceName": transport.get("service_name", "")}
        if profile.options.get("grpc_mode") == "multi":
            stream["grpcSettings"]["multiMode"] = True
        if profile.options.get("grpc_authority"):
            stream["grpcSettings"]["authority"] = profile.options["grpc_authority"]
    elif kind == "httpupgrade":
        stream["httpupgradeSettings"] = {"path": transport.get("path", "/"),
                                         "host": transport.get("host", "")}
    common = {"serverName": tls.get("server_name", ""),
              "fingerprint": tls.get("utls", {}).get("fingerprint", "chrome")}
    if "reality" in tls:
        if "alpn" in tls:
            raise UserError("Reality в Xray использует ALPN выбранного fingerprint; отдельный alpn не поддерживается.")
        reality = tls["reality"]
        stream["realitySettings"] = {**common, "publicKey": reality["public_key"],
            "shortId": reality["short_id"], "spiderX": profile.options.get("spx", "/")}
        # support-x25519mlkem768 is a capability hint, not a wire setting.
        # The pinned Xray release supports hybrid key shares in the chosen fingerprint.
    elif tls:
        if tls.get("insecure"):
            raise UserError("Xray 26.3.27 требует проверку TLS-сертификата; allowInsecure для этого профиля не поддерживается.")
        stream["tlsSettings"] = {**common, "allowInsecure": tls.get("insecure", False)}
        if "alpn" in tls:
            stream["tlsSettings"]["alpn"] = tls["alpn"]
        if "ech" in tls:
            stream["tlsSettings"]["echConfigList"] = xray_ech_config(tls["ech"])
            stream["tlsSettings"]["echForceQuery"] = "full"
    if profile.protocol == "vless":
        user = {"id": outbound["uuid"], "encryption": profile.options.get("encryption", "none")}
        if outbound.get("flow"):
            user["flow"] = outbound["flow"]
        if outbound.get("packet_encoding") == "packetaddr":
            raise UserError("Xray не поддерживает packetEncoding=packetaddr для этого профиля.")
        proxy_settings = {"vnext": [{"address": outbound["server"], "port": outbound["server_port"], "users": [user]}]}
    elif profile.protocol == "trojan":
        proxy_settings = {"servers": [{"address": outbound["server"], "port": outbound["server_port"],
                                       "password": outbound["password"]}]}
    else:
        raise UserError("Мост Xray поддерживает VLESS и Trojan.")
    dns = {"servers": ["tcp+local://" + ("[" + settings.bootstrap_dns + "]" if ":" in settings.bootstrap_dns else settings.bootstrap_dns)],
           "queryStrategy": "UseIP" if settings.ipv6 else "UseIPv4"}
    if endpoint_hosts is not None:
        # Keep the original domain for TLS/XHTTP, without querying blocked DNS
        # sockets once Windows TUN has enabled its leak protection.
        dns["hosts"] = deepcopy(endpoint_hosts)
        dns["servers"] = []
    return {
        "log": {"loglevel": "warning"},
        # Local mode resolves the VPN endpoint outside its own tunnel, including
        # on Android, where the Go system resolver may expose a loopback server.
        "dns": dns,
        "inbounds": [{"tag": "sever-sidecar", "listen": "127.0.0.1", "port": port,
            "protocol": "socks", "settings": {"auth": "password", "accounts": [
                {"user": "sever", "pass": password}], "udp": True, "ip": "127.0.0.1"}}],
        "outbounds": [{"tag": "proxy", "protocol": profile.protocol, "settings": proxy_settings,
            "streamSettings": stream}],
    }


def sidecar_outbound(port: int, password: str) -> dict:
    return {"type": "socks", "server": "127.0.0.1", "server_port": port,
            "version": "5", "username": "sever", "password": password}
