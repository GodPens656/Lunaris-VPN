from copy import deepcopy

from .models import Profile, Settings, UserError
from .routing import RUSSIAN_DOMAIN_SUFFIXES


def build_config(profile: Profile, settings: Settings, api_secret: str, *, android: bool = False, sidecar: dict | None = None, endpoint_hosts: dict | None = None) -> dict:
    settings.validate()
    if profile.requires_xray and sidecar is None:
        raise UserError("Для этого профиля требуется запуск Xray вместе с sing-box.")
    proxy = deepcopy(sidecar if sidecar is not None else profile.outbound)
    proxy["tag"] = "proxy"
    if android and sidecar is not None:
        # This is a local SOCKS bridge, not a physical-network connection.
        # Explicit binding disables libbox's Android interface selection for
        # both TCP and the SOCKS UDP relay (including tunneled UDP DNS).
        proxy["inet4_bind_address"] = "127.0.0.1"
    remote = {"type": settings.dns_kind, "tag": "remote", "server": settings.dns_server, "detour": "proxy"}
    if settings.dns_kind in {"https", "tls"}:
        remote["tls"] = {"enabled": True, "server_name": settings.dns_tls_name}
    if settings.dns_kind == "https":
        remote["path"] = "/dns-query"
    inbounds = [{"type": "mixed", "tag": "local-proxy", "listen": "127.0.0.1", "listen_port": settings.mixed_port}]
    if settings.mode == "tun" or android:
        inbounds.append({
            "type": "tun", "tag": "tun-in", "interface_name": "LunarisVPN",
            "address": ["172.19.0.1/30"] + (["fdfe:dcba:9876::1/126"] if settings.ipv6 else []),
            # Android's packet path must not depend on kernel TCP redirection.
            # This also applies when Xray/Mihomo supplies the SOCKS outbound.
            "mtu": 1500, "auto_route": True, "strict_route": True, "stack": "gvisor" if android else "mixed",
        })
        if android:
            inbounds[-1].update(dns_mode="hijack", dns_address=["172.19.0.2"])
    rules = [{"action": "sniff"}, {"protocol": "dns", "action": "hijack-dns"}]
    direct = {"type": "direct", "tag": "direct"}
    if settings.bypass_russian_domains:
        rules.append({"domain_suffix": list(RUSSIAN_DOMAIN_SUFFIXES), "action": "route", "outbound": "direct"})
        # In Windows TUN, bootstrap contains only pre-resolved VPN endpoints.
        # Website names must use the existing DNS server through the proxy.
        direct["domain_resolver"] = "remote"
    if profile.requires_xray and not android:
        # Xray's physical sockets (including bootstrap DNS) must not loop into the TUN.
        rules.insert(0, {"process_name": ["xray.exe"], "action": "route", "outbound": "direct"})
    bootstrap = {"type": "udp", "tag": "bootstrap", "server": settings.bootstrap_dns}
    if endpoint_hosts is not None:
        # Windows strict_route blocks port 53 on physical interfaces. Resolve the
        # VPN endpoint before starting TUN, then use only these session addresses.
        bootstrap = {"type": "hosts", "tag": "bootstrap", "predefined": deepcopy(endpoint_hosts)}
    return {
        "log": {"level": "info", "timestamp": False},
        "dns": {"servers": [bootstrap, remote], "final": "remote", "strategy": "prefer_ipv4" if settings.ipv6 else "ipv4_only"},
        "inbounds": inbounds,
        "outbounds": [proxy, direct],
        "route": {"auto_detect_interface": settings.mode == "tun" or android, "default_domain_resolver": "bootstrap", "final": "proxy", "rules": rules},
        "experimental": {"clash_api": {"external_controller": f"127.0.0.1:{settings.api_port}", "secret": api_secret}},
    }
