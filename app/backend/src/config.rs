use crate::{
    models::{Profile, Settings},
    Result,
};
use serde_json::{json, Value};
pub const RUSSIAN_SUFFIXES: [&str; 3] = ["xn--p1ai", "su", "ru"];
fn s<'a>(v: &'a Value, k: &str, default: &'a str) -> &'a str {
    v.get(k).and_then(Value::as_str).unwrap_or(default)
}
pub fn sidecar(port: u16, password: &str) -> Value {
    json!({"type":"socks","server":"127.0.0.1","server_port":port,"version":"5","username":"sever","password":password})
}
pub fn sing_box(
    p: &Profile,
    settings: &Settings,
    secret: &str,
    android: bool,
    sidecar: Option<Value>,
    hosts: Option<&Value>,
) -> Result<Value> {
    settings.validate()?;
    if p.requires_xray() && sidecar.is_none() {
        return Err("Для этого профиля требуется запуск Xray вместе с sing-box.".into());
    }
    let local = sidecar.is_some();
    let mut proxy = sidecar.unwrap_or_else(|| p.outbound.clone());
    proxy["tag"] = json!("proxy");
    if android && local {
        proxy["inet4_bind_address"] = json!("127.0.0.1");
    }
    let mut remote = json!({"type":settings.dns_kind,"tag":"remote","server":settings.dns_server,"detour":"proxy"});
    if settings.dns_kind != "udp" {
        remote["tls"] = json!({"enabled":true,"server_name":settings.dns_tls_name});
    }
    if settings.dns_kind == "https" {
        remote["path"] = json!("/dns-query");
    }
    let mut inbounds = vec![
        json!({"type":"mixed","tag":"local-proxy","listen":"127.0.0.1","listen_port":settings.mixed_port}),
    ];
    if settings.mode == "tun" || android {
        let mut addresses = vec!["172.19.0.1/30"];
        if settings.ipv6 {
            addresses.push("fdfe:dcba:9876::1/126");
        }
        let mut tun = json!({"type":"tun","tag":"tun-in","interface_name":"LunarisVPN","address":addresses,"mtu":1500,"auto_route":true,"strict_route":true,"stack":if android{"gvisor"}else{"mixed"}});
        if android {
            tun["dns_mode"] = json!("hijack");
            tun["dns_address"] = json!(["172.19.0.2"]);
        }
        inbounds.push(tun);
    }
    let mut rules = vec![
        json!({"action":"sniff"}),
        json!({"protocol":"dns","action":"hijack-dns"}),
    ];
    let mut direct = json!({"type":"direct","tag":"direct"});
    if settings.bypass_russian_domains {
        rules.push(json!({"domain_suffix":RUSSIAN_SUFFIXES,"action":"route","outbound":"direct"}));
        direct["domain_resolver"] = json!("remote");
    }
    if p.requires_xray() && !android {
        rules.insert(
            0,
            json!({"process_name":["xray.exe"],"action":"route","outbound":"direct"}),
        );
    }
    let bootstrap = hosts
        .map(|h| json!({"type":"hosts","tag":"bootstrap","predefined":h}))
        .unwrap_or_else(|| json!({"type":"udp","tag":"bootstrap","server":settings.bootstrap_dns}));
    Ok(
        json!({"log":{"level":"info","timestamp":false},"dns":{"servers":[bootstrap,remote],"final":"remote","strategy":if settings.ipv6{"prefer_ipv4"}else{"ipv4_only"}},"inbounds":inbounds,"outbounds":[proxy,direct],"route":{"auto_detect_interface":settings.mode=="tun"||android,"default_domain_resolver":"bootstrap","final":"proxy","rules":rules},"experimental":{"clash_api":{"external_controller":format!("127.0.0.1:{}",settings.api_port),"secret":secret}}}),
    )
}
pub fn xray(
    p: &Profile,
    port: u16,
    password: &str,
    settings: &Settings,
    hosts: Option<&Value>,
) -> Result<Value> {
    if !p.requires_xray() {
        return Err("Этот профиль не требует Xray.".into());
    }
    settings.validate()?;
    let o = &p.outbound;
    let tls = &o["tls"];
    let mut tr = o.get("transport").cloned().unwrap_or(json!({"type":"tcp"}));
    let kind = s(&tr, "type", "tcp").to_string();
    tr.as_object_mut()
        .ok_or("Некорректный транспорт.")?
        .remove("type");
    if !["tcp", "xhttp", "ws", "grpc", "httpupgrade"].contains(&kind.as_str()) {
        return Err("Мост Xray поддерживает TCP, XHTTP, WS, gRPC и HTTPUpgrade.".into());
    }
    let mut stream = json!({"network":if kind=="tcp"{"raw"}else{&kind},"security":if tls.get("reality").is_some(){"reality"}else if tls.is_object(){"tls"}else{"none"},"sockopt":{"domainStrategy":if settings.ipv6{"UseIP"}else{"UseIPv4"}}});
    match kind.as_str() {
        "xhttp" => stream["xhttpSettings"] = tr.clone(),
        "ws" => {
            if tr["max_early_data"].as_u64().unwrap_or(0) > 0 {
                return Err("WebSocket early data через мост Xray пока не поддерживается.".into());
            }
            stream["wsSettings"] = json!({"path":s(&tr,"path","/"),"headers":tr.get("headers").cloned().unwrap_or(json!({}))});
        }
        "grpc" => {
            let mut g = json!({"serviceName":s(&tr,"service_name","")});
            if p.options["grpc_mode"] == "multi" {
                g["multiMode"] = json!(true);
            }
            if let Some(a) = p.options.get("grpc_authority") {
                g["authority"] = a.clone();
            }
            stream["grpcSettings"] = g;
        }
        "httpupgrade" => {
            stream["httpupgradeSettings"] =
                json!({"path":s(&tr,"path","/"),"host":s(&tr,"host","")})
        }
        _ => {}
    }
    let common = json!({"serverName":s(tls,"server_name",""),"fingerprint":s(&tls["utls"],"fingerprint","chrome")});
    if let Some(r) = tls.get("reality") {
        if tls.get("alpn").is_some() {
            return Err("Reality в Xray использует ALPN выбранного fingerprint; отдельный alpn не поддерживается.".into());
        }
        let mut rsettings = common;
        rsettings["publicKey"] = r["public_key"].clone();
        rsettings["shortId"] = r["short_id"].clone();
        rsettings["spiderX"] = json!(s(&p.options, "spx", "/"));
        stream["realitySettings"] = rsettings;
    } else if tls.is_object() {
        if tls["insecure"] == true {
            return Err("Xray 26.3.27 требует проверку TLS-сертификата; allowInsecure для этого профиля не поддерживается.".into());
        }
        let mut t = common;
        t["allowInsecure"] = json!(false);
        if let Some(a) = tls.get("alpn") {
            t["alpn"] = a.clone();
        }
        if let Some(e) = tls.get("ech") {
            let a = e["config"]
                .as_array()
                .filter(|a| a.len() == 1)
                .ok_or("Xray требует один ECHConfigList.")?;
            let text = a[0].as_str().ok_or("Некорректный ECHConfigList.")?;
            let lines: Vec<_> = text.lines().collect();
            if e["enabled"] != true
                || lines.len() < 3
                || lines[0] != "-----BEGIN ECH CONFIGS-----"
                || lines.last() != Some(&"-----END ECH CONFIGS-----")
            {
                return Err("Некорректный ECHConfigList.".into());
            }
            let encoded = lines[1..lines.len() - 1].join("");
            crate::parser::ech(&encoded)?;
            t["echConfigList"] = json!(encoded);
            t["echForceQuery"] = json!("full");
        }
        stream["tlsSettings"] = t;
    }
    let proxy = if p.protocol() == "vless" {
        if o["packet_encoding"] == "packetaddr" {
            return Err("Xray не поддерживает packetEncoding=packetaddr для этого профиля.".into());
        }
        let mut user = json!({"id":o["uuid"],"encryption":s(&p.options,"encryption","none")});
        if let Some(f) = o.get("flow") {
            user["flow"] = f.clone();
        }
        json!({"vnext":[{"address":o["server"],"port":o["server_port"],"users":[user]}]})
    } else if p.protocol() == "trojan" {
        json!({"servers":[{"address":o["server"],"port":o["server_port"],"password":o["password"]}]})
    } else {
        return Err("Мост Xray поддерживает VLESS и Trojan.".into());
    };
    let bootstrap = if settings.bootstrap_dns.contains(':') {
        format!("[{}]", settings.bootstrap_dns)
    } else {
        settings.bootstrap_dns.clone()
    };
    let mut dns = json!({"servers":[format!("tcp+local://{bootstrap}")],"queryStrategy":if settings.ipv6{"UseIP"}else{"UseIPv4"}});
    if let Some(h) = hosts {
        dns["hosts"] = h.clone();
        dns["servers"] = json!([]);
    }
    Ok(
        json!({"log":{"loglevel":"warning"},"dns":dns,"inbounds":[{"tag":"sever-sidecar","listen":"127.0.0.1","port":port,"protocol":"socks","settings":{"auth":"password","accounts":[{"user":"sever","pass":password}],"udp":true,"ip":"127.0.0.1"}}],"outbounds":[{"tag":"proxy","protocol":p.protocol(),"settings":proxy,"streamSettings":stream}]}),
    )
}
pub fn mihomo_proxy(p: &Profile) -> Result<Value> {
    if p.xray_grpc() {
        return Err("gRPC mode=multi и authority требуют sing-box / Xray.".into());
    }
    let o = &p.outbound;
    let kind = p.protocol();
    if !["vless", "trojan", "hysteria2"].contains(&kind) {
        return Err("Mihomo поддерживает VLESS, Trojan и Hysteria2.".into());
    }
    let mut proxy =
        json!({"name":"proxy","type":kind,"server":o["server"],"port":o["server_port"],"udp":true});
    if kind == "vless" {
        proxy["uuid"] = o["uuid"].clone();
        if p.options.get("encryption").is_some() {
            proxy["encryption"] = p.options["encryption"].clone();
        }
        if let Some(f) = o.get("flow") {
            proxy["flow"] = f.clone();
        }
        proxy["packet-encoding"] = json!(s(o, "packet_encoding", "xudp"));
    } else {
        proxy["password"] = o["password"].clone();
    }
    if let Some(tls) = o.get("tls") {
        if kind == "vless" {
            proxy["tls"] = tls.get("enabled").cloned().unwrap_or(json!(true));
        }
        proxy[if kind == "vless" { "servername" } else { "sni" }] =
            json!(s(tls, "server_name", s(o, "server", "")));
        proxy["skip-cert-verify"] = tls.get("insecure").cloned().unwrap_or(json!(false));
        if let Some(a) = tls.get("alpn") {
            proxy["alpn"] = a.clone();
        }
        if tls.get("utls").is_some() {
            proxy["client-fingerprint"] =
                if tls.get("reality").is_some() && p.options["support-x25519mlkem768"] == true {
                    json!("chrome")
                } else {
                    tls["utls"]["fingerprint"].clone()
                };
        }
        if let Some(r) = tls.get("reality") {
            let mut r = json!({"public-key":r["public_key"],"short-id":r["short_id"]});
            if let Some(v) = p.options.get("support-x25519mlkem768") {
                r["support-x25519mlkem768"] = v.clone();
            }
            proxy["reality-opts"] = r;
        }
        if let Some(e) = tls.get("ech") {
            let a = e["config"]
                .as_array()
                .filter(|a| a.len() == 1)
                .ok_or("Mihomo требует один ECHConfigList.")?;
            let lines: Vec<_> = a[0]
                .as_str()
                .ok_or("Некорректный ECHConfigList.")?
                .lines()
                .collect();
            if lines.len() < 3 {
                return Err("Некорректный ECHConfigList.".into());
            }
            proxy["ech-opts"] = json!({"enable":true,"config":lines[1..lines.len()-1].join("")});
        }
    }
    if let Some(o) = o.get("obfs") {
        proxy["obfs"] = o["type"].clone();
        proxy["obfs-password"] = o["password"].clone();
    }
    let tr = &o["transport"];
    let network = s(tr, "type", "tcp");
    let tls = o.get("tls").is_some();
    if kind == "trojan" && !["tcp", "ws", "httpupgrade", "grpc"].contains(&network) {
        return Err("Mihomo поддерживает Trojan с TCP, WS, HTTPUpgrade и gRPC.".into());
    }
    match network {
        "ws" | "httpupgrade" => {
            proxy["network"] = json!("ws");
            let mut w = json!({"path":s(tr,"path","/")});
            if network == "httpupgrade" {
                w["v2ray-http-upgrade"] = json!(true);
                if tr.get("host").is_some() {
                    w["headers"] = json!({"Host":tr["host"]});
                }
            } else {
                for (a, b) in [
                    ("headers", "headers"),
                    ("max_early_data", "max-early-data"),
                    ("early_data_header_name", "early-data-header-name"),
                ] {
                    if let Some(v) = tr.get(a) {
                        w[b] = v.clone();
                    }
                }
            }
            proxy["ws-opts"] = w;
        }
        "grpc" => {
            proxy["network"] = json!("grpc");
            proxy["grpc-opts"] = json!({"grpc-service-name":s(tr,"service_name","")});
        }
        "http" => {
            let hosts = tr.get("host").cloned().unwrap_or(json!([o["server"]]));
            if tls {
                proxy["network"] = json!("h2");
                proxy["h2-opts"] = json!({"path":s(tr,"path","/"),"host":hosts});
            } else {
                proxy["network"] = json!("http");
                proxy["http-opts"] = json!({"path":[s(tr,"path","/")],"headers":{"Host":hosts}});
            }
        }
        "xhttp" => {
            proxy["network"] = json!("xhttp");
            let mut x =
                json!({"path":s(tr,"path","/"),"host":s(tr,"host",""),"mode":s(tr,"mode","auto")});
            if let Some(v) = tr["extra"].get("xPaddingBytes") {
                x["x-padding-bytes"] = v.clone();
            }
            proxy["xhttp-opts"] = x;
        }
        "tcp" => {}
        _ => return Err("Транспорт этого сервера не поддерживается Mihomo.".into()),
    }
    Ok(proxy)
}
pub fn mihomo(
    p: &Profile,
    settings: &Settings,
    secret: &str,
    hosts: Option<&Value>,
) -> Result<Value> {
    settings.validate()?;
    let mut proxies = vec![mihomo_proxy(p)?];
    let mut hosts = hosts.cloned().unwrap_or(json!({}));
    let remote = if settings.dns_kind == "udp" {
        let ip = if settings.dns_server.contains(':') {
            format!("[{}]", settings.dns_server)
        } else {
            settings.dns_server.clone()
        };
        format!("udp://{ip}:53#proxy")
    } else {
        let name = &settings.dns_tls_name;
        if hosts.get(name).is_some_and(|v| {
            !v.as_array()
                .is_some_and(|a| a.contains(&json!(settings.dns_server)))
        }) {
            return Err("TLS-имя DNS совпадает с адресом VPN-сервера, но IP различаются.".into());
        }
        hosts[name] = json!([settings.dns_server]);
        proxies.push(json!({"name":"dns-via-proxy","type":"direct","dialer-proxy":"proxy"}));
        if settings.dns_kind == "https" {
            format!("https://{name}/dns-query#dns-via-proxy")
        } else {
            format!("tls://{name}:853#dns-via-proxy")
        }
    };
    let bootstrap = if settings.bootstrap_dns.contains(':') {
        format!("[{}]", settings.bootstrap_dns)
    } else {
        settings.bootstrap_dns.clone()
    };
    let mut c = json!({"mixed-port":settings.mixed_port,"bind-address":"127.0.0.1","allow-lan":false,"mode":"rule","log-level":"info","ipv6":settings.ipv6,"external-controller":format!("127.0.0.1:{}",settings.api_port),"secret":secret,"profile":{"store-selected":false,"store-fake-ip":false},"hosts":hosts,"proxies":proxies,"rules":["MATCH,proxy"],"dns":{"enable":true,"ipv6":settings.ipv6,"enhanced-mode":"redir-host","use-hosts":true,"use-system-hosts":false,"default-nameserver":[format!("udp://{bootstrap}:53")],"proxy-server-nameserver":[format!("udp://{bootstrap}:53")],"nameserver":[remote]},"tun":{"enable":settings.mode=="tun","device":"LunarisVPN","stack":"mixed","auto-route":true,"auto-detect-interface":true,"strict-route":true,"mtu":1500,"dns-hijack":["any:53","tcp://any:53"]}});
    if settings.ipv6 {
        c["tun"]["inet6-address"] = json!(["fdfe:dcba:9876::1/126"]);
    }
    if settings.bypass_russian_domains {
        let mut rules = RUSSIAN_SUFFIXES
            .iter()
            .map(|s| format!("DOMAIN-SUFFIX,{s},DIRECT"))
            .collect::<Vec<_>>();
        rules.push("MATCH,proxy".into());
        c["rules"] = json!(rules);
        c["sniffer"] = json!({"enable":true,"force-dns-mapping":true,"parse-pure-ip":true,"override-destination":false,"sniff":{"HTTP":{"ports":["1-65535"]},"TLS":{"ports":["1-65535"]},"QUIC":{"ports":["1-65535"]}}});
    }
    Ok(c)
}
pub fn android(p: &Profile, settings: &Settings, secret: &str, password: &str) -> Result<Value> {
    let mut settings = settings.clone();
    settings.mode = "tun".into();
    if p.xray_grpc() {
        settings.core = "sing-box".into();
    }
    let bridge = settings.core == "mihomo" || p.requires_xray();
    let mut c = sing_box(
        p,
        &settings,
        secret,
        true,
        bridge.then(|| sidecar(0, password)),
        None,
    )?;
    if settings.core == "mihomo" {
        let mut m = mihomo(p, &settings, "", None)?;
        let map = m.as_object_mut().unwrap();
        map.remove("external-controller");
        map.remove("secret");
        m["mixed-port"] = json!(0);
        m["authentication"] = json!([format!("sever:{password}")]);
        m["tun"] = json!({"enable":false});
        c["sever_mihomo"] = m;
    } else if p.requires_xray() {
        c["sever_xray"] = xray(p, 0, password, &settings, None)?;
    }
    Ok(c)
}
