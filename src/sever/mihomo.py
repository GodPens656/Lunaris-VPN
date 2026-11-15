"""Translate validated share profiles to the pinned Mihomo configuration schema."""
from copy import deepcopy

from .models import Profile, Settings, UserError
from .routing import RUSSIAN_DOMAIN_SUFFIXES

MIHOMO_VERSION = "1.19.32"


def effective_client_fingerprint(profile: Profile) -> str | None:
    tls = profile.outbound.get("tls", {})
    fingerprint = tls.get("utls", {}).get("fingerprint")
    # v1.19.32 pins metacubex/utls v1.8.8. Only its Chrome Auto
    # fingerprint offers X25519MLKEM768. The support flag preserves an
    # existing key share; it cannot add one to Firefox/Safari/etc.
    # Keep absent/false hints unchanged for older REALITY servers.
    if "reality" in tls and profile.options.get("support-x25519mlkem768") is True:
        return "chrome"
    return fingerprint


def build_proxy(profile: Profile) -> dict:
    if profile.requires_xray_grpc:
        raise UserError("gRPC mode=multi и authority требуют sing-box / Xray.")
    outbound = profile.outbound
    kind = profile.protocol
    if kind not in {"vless", "trojan", "hysteria2"}:
        raise UserError("Mihomo поддерживает профили VLESS, Trojan и Hysteria2.")
    # spiderX only controls Xray's website crawler after failed REALITY auth.
    # It is not sent in an authenticated handshake. Mihomo has no equivalent
    # crawler option; keep spx in the saved profile without blocking this core.
    proxy = {"name": "proxy", "type": kind, "server": outbound["server"],
             "port": outbound["server_port"], "udp": True}
    if kind == "vless":
        proxy["uuid"] = outbound["uuid"]
        if profile.options.get("encryption", "none") != "none":
            proxy["encryption"] = profile.options["encryption"]
        if outbound.get("flow"):
            proxy["flow"] = outbound["flow"]
        # Preserve sing-box's default XUDP encoding explicitly.
        proxy["packet-encoding"] = outbound.get("packet_encoding", "xudp")
    else:
        proxy["password"] = outbound["password"]
    tls = outbound.get("tls", {})
    if tls:
        if kind == "vless":
            proxy["tls"] = tls.get("enabled", True)
        proxy["servername" if kind == "vless" else "sni"] = tls.get("server_name", outbound["server"])
        proxy["skip-cert-verify"] = tls.get("insecure", False)
        if "alpn" in tls:
            proxy["alpn"] = deepcopy(tls["alpn"])
        if "utls" in tls:
            proxy["client-fingerprint"] = effective_client_fingerprint(profile)
        if "reality" in tls:
            reality = tls["reality"]
            proxy["reality-opts"] = {"public-key": reality["public_key"], "short-id": reality["short_id"]}
            if "support-x25519mlkem768" in profile.options:
                proxy["reality-opts"]["support-x25519mlkem768"] = profile.options["support-x25519mlkem768"]
        if "ech" in tls:
            configs = tls["ech"].get("config", [])
            if len(configs) != 1:
                raise UserError("Mihomo требует один ECHConfigList для этого профиля.")
            proxy["ech-opts"] = {"enable": True, "config": "".join(configs[0].splitlines()[1:-1])}
    if "obfs" in outbound:
        proxy["obfs"] = outbound["obfs"]["type"]
        proxy["obfs-password"] = outbound["obfs"]["password"]
    # Hy2 fp is a share-link capability hint, not a QUIC TLS wire setting.
    transport = outbound.get("transport", {})
    network = transport.get("type", "tcp")
    if kind == "trojan" and network not in {"tcp", "ws", "httpupgrade", "grpc"}:
        raise UserError("Mihomo поддерживает Trojan с TCP, WS, HTTPUpgrade и gRPC. Для HTTP выберите sing-box / Xray.")
    if network in {"ws", "httpupgrade"}:
        proxy["network"] = "ws"
        options = {"path": transport.get("path", "/")}
        if network == "httpupgrade":
            options["v2ray-http-upgrade"] = True
            if transport.get("host"):
                options["headers"] = {"Host": transport["host"]}
        else:
            for source, target in [("headers", "headers"), ("max_early_data", "max-early-data"),
                                   ("early_data_header_name", "early-data-header-name")]:
                if source in transport:
                    options[target] = deepcopy(transport[source])
        proxy["ws-opts"] = options
    elif network == "grpc":
        proxy["network"] = "grpc"
        proxy["grpc-opts"] = {"grpc-service-name": transport.get("service_name", "")}
    elif network == "http":
        if tls:
            proxy["network"] = "h2"
            proxy["h2-opts"] = {"path": transport.get("path", "/"),
                                "host": deepcopy(transport.get("host", [outbound["server"]]))}
        else:
            proxy["network"] = "http"
            proxy["http-opts"] = {"path": [transport.get("path", "/")],
                                  "headers": {"Host": deepcopy(transport.get("host", [outbound["server"]]))}}
    elif network == "xhttp":
        proxy["network"] = "xhttp"
        proxy["xhttp-opts"] = {"path": transport.get("path", "/"), "host": transport.get("host", ""),
                               "mode": transport.get("mode", "auto")}
        if "xPaddingBytes" in transport.get("extra", {}):
            proxy["xhttp-opts"]["x-padding-bytes"] = transport["extra"]["xPaddingBytes"]
    elif network != "tcp":
        raise UserError("Транспорт этого сервера не поддерживается Mihomo. Выберите sing-box / Xray.")
    return proxy


def build_mihomo_config(profile: Profile, settings: Settings, api_secret: str, *, endpoint_hosts: dict | None = None) -> dict:
    settings.validate()
    proxy = build_proxy(profile)
    proxies = [proxy]
    hosts = deepcopy(endpoint_hosts or {})
    if settings.dns_kind == "udp":
        address = f"[{settings.dns_server}]" if ":" in settings.dns_server else settings.dns_server
        remote = f"udp://{address}:53#proxy"
    else:
        # Resolving this name from hosts preserves DNS TLS SNI and certificate
        # verification while dialing the configured IP without bootstrap DNS.
        name = settings.dns_tls_name
        if name in hosts and settings.dns_server not in hosts[name]:
            raise UserError("TLS-имя DNS совпадает с адресом VPN-сервера, но IP различаются. Измените DNS в настройках.")
        hosts[name] = [settings.dns_server]
        # The direct adapter is L3: DNSDialer resolves hosts and clears the
        # domain before dialing. Its dialer-proxy then carries that pinned IP
        # through the selected VPN, while the DNS client retains its TLS SNI.
        proxies.append({"name": "dns-via-proxy", "type": "direct", "dialer-proxy": "proxy"})
        remote = f"https://{name}/dns-query#dns-via-proxy" if settings.dns_kind == "https" else f"tls://{name}:853#dns-via-proxy"
    bootstrap = f"[{settings.bootstrap_dns}]" if ":" in settings.bootstrap_dns else settings.bootstrap_dns
    config = {
        "mixed-port": settings.mixed_port, "bind-address": "127.0.0.1", "allow-lan": False,
        "mode": "rule", "log-level": "info", "ipv6": settings.ipv6,
        "external-controller": f"127.0.0.1:{settings.api_port}", "secret": api_secret,
        "profile": {"store-selected": False, "store-fake-ip": False},
        "hosts": hosts, "proxies": proxies, "rules": ["MATCH,proxy"],
        "dns": {"enable": True, "ipv6": settings.ipv6, "enhanced-mode": "redir-host",
                "use-hosts": True, "use-system-hosts": False,
                "default-nameserver": [f"udp://{bootstrap}:53"],
                "proxy-server-nameserver": [f"udp://{bootstrap}:53"], "nameserver": [remote]},
        "tun": {"enable": settings.mode == "tun", "device": "LunarisVPN", "stack": "mixed",
                "auto-route": True, "auto-detect-interface": True, "strict-route": True, "mtu": 1500,
                "dns-hijack": ["any:53", "tcp://any:53"]},
    }
    if settings.ipv6:
        config["tun"]["inet6-address"] = ["fdfe:dcba:9876::1/126"]
    if settings.bypass_russian_domains:
        config["rules"] = [f"DOMAIN-SUFFIX,{suffix},DIRECT" for suffix in RUSSIAN_DOMAIN_SUFFIXES] + ["MATCH,proxy"]
        # Recover HTTP Host / TLS SNI for TUN connections addressed by IP.
        config["sniffer"] = {
            "enable": True, "force-dns-mapping": True, "parse-pure-ip": True,
            "override-destination": False,
            "sniff": {protocol: {"ports": ["1-65535"]} for protocol in ("HTTP", "TLS", "QUIC")},
        }
    return config


def build_mihomo_sidecar(profile: Profile, settings: Settings, password: str) -> dict:
    """Android's service reserves port 0 before starting this SOCKS bridge."""
    config = build_mihomo_config(profile, settings, "")
    config["mixed-port"] = 0
    config["authentication"] = [f"sever:{password}"]
    config.pop("external-controller")
    config.pop("secret")
    config["tun"] = {"enable": False}
    return config
