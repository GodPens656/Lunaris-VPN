//! Conservative share-link import. Unknown fields are rejected, never discarded.
use crate::{
    models::{ImportReport, Profile, Rejection},
    Result,
};
use base64::{
    engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD},
    Engine,
};
use regex::Regex;
use serde_json::{json, Value};
use std::collections::{BTreeMap, HashSet};

pub const MAX_BODY: usize = 2 * 1024 * 1024;
const TLS: &[&str] = &[
    "sni",
    "peer",
    "alpn",
    "fp",
    "allowInsecure",
    "insecure",
    "ech",
];
const REALITY: &[&str] = &["pbk", "sid", "spx", "support-x25519mlkem768"];
const TRANSPORT: &[&str] = &[
    "type",
    "path",
    "host",
    "serviceName",
    "authority",
    "mode",
    "headerType",
    "ed",
    "eh",
    "extra",
    "x_padding_bytes",
];
type Query = BTreeMap<String, String>;
fn get<'a>(q: &'a Query, key: &str, default: &'a str) -> &'a str {
    q.get(key).map(String::as_str).unwrap_or(default)
}
fn any(q: &Query, keys: &[&str]) -> bool {
    keys.iter().any(|k| q.contains_key(*k))
}
pub fn unbase64(value: &str) -> Result<Vec<u8>> {
    [STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD]
        .iter()
        .find_map(|e| e.decode(value).ok())
        .ok_or_else(|| "Некорректный Base64.".into())
}
pub fn decode(value: &str) -> Result<String> {
    let bytes = value.as_bytes();
    let mut result = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            if i + 2 >= bytes.len() {
                return Err("Некорректный percent-encoding.".into());
            }
            let digit = |b: u8| (b as char).to_digit(16).map(|n| n as u8);
            let (a, b) = (digit(bytes[i + 1]), digit(bytes[i + 2]));
            result.push(
                a.zip(b)
                    .map(|(a, b)| a * 16 + b)
                    .ok_or("Некорректный percent-encoding.")?,
            );
            i += 3;
        } else {
            result.push(bytes[i]);
            i += 1;
        }
    }
    let s = String::from_utf8(result).map_err(|_| "Некорректная UTF-8 строка.")?;
    if s.chars().any(char::is_control) {
        return Err("Управляющие символы в ссылке запрещены.".into());
    }
    Ok(s)
}
pub fn boolean(s: &str) -> Result<bool> {
    match s {
        "1" | "true" => Ok(true),
        "0" | "false" => Ok(false),
        _ => Err("Булевый параметр должен быть 0/1 или true/false.".into()),
    }
}
pub fn host(s: &str) -> Result<String> {
    let decoded = decode(s)?;
    let value = decoded.trim().trim_matches(['[', ']']);
    if let Ok(ip) = value.parse::<std::net::IpAddr>() {
        return Ok(ip.to_string());
    }
    let h = url::Host::parse(value.trim_end_matches('.'))
        .map_err(|_| "Некорректный адрес сервера.")?
        .to_string()
        .to_lowercase();
    let label = Regex::new(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$").unwrap();
    if h.len() > 253 || h.is_empty() || h.split('.').any(|s| !label.is_match(s)) {
        return Err("Некорректный адрес сервера.".into());
    }
    Ok(h)
}
fn alias<'a>(q: &'a Query, a: &str, b: &str, default: &'a str) -> Result<&'a str> {
    if q.contains_key(a) && q.contains_key(b) {
        return Err("Одновременно заданы дублирующие параметры.".into());
    }
    Ok(q.get(a)
        .or_else(|| q.get(b))
        .map(String::as_str)
        .unwrap_or(default))
}
pub fn ech(value: &str) -> Result<Value> {
    let raw = STANDARD
        .decode(value)
        .map_err(|_| "Некорректный ECHConfigList.")?;
    if raw.len() < 6 || u16::from_be_bytes([raw[0], raw[1]]) as usize != raw.len() - 2 {
        return Err("Некорректный ECHConfigList.".into());
    }
    let mut i = 2;
    while i < raw.len() {
        if i + 4 > raw.len() {
            return Err("Некорректный ECHConfigList.".into());
        }
        let size = u16::from_be_bytes([raw[i + 2], raw[i + 3]]) as usize;
        if size == 0 || i + 4 + size > raw.len() {
            return Err("Некорректный ECHConfigList.".into());
        }
        i += 4 + size;
    }
    let encoded = STANDARD.encode(raw);
    let lines = encoded
        .as_bytes()
        .chunks(64)
        .map(|s| std::str::from_utf8(s).unwrap())
        .collect::<Vec<_>>()
        .join("\n");
    Ok(
        json!({"enabled":true,"config":[format!("-----BEGIN ECH CONFIGS-----\n{lines}\n-----END ECH CONFIGS-----")]}),
    )
}
fn tls(q: &Query, server: &str, security: &str) -> Result<Option<Value>> {
    if security == "none" {
        if any(q, TLS) || any(q, REALITY) {
            return Err("TLS-параметры заданы при отключённом TLS.".into());
        }
        return Ok(None);
    }
    if !matches!(security, "tls" | "reality") {
        return Err("Неподдерживаемый тип безопасности.".into());
    }
    let mut t = json!({"enabled":true,"server_name":host(alias(q,"sni","peer",server)?)?});
    if boolean(alias(q, "insecure", "allowInsecure", "0")?)? {
        t["insecure"] = json!(true);
    }
    if let Some(alpn) = q.get("alpn") {
        let values: Vec<_> = alpn.split(',').collect();
        if values.iter().any(|s| s.is_empty() || s.len() > 255) {
            return Err("Некорректный ALPN.".into());
        }
        t["alpn"] = json!(values);
    }
    if let Some(e) = q.get("ech") {
        if security != "tls" {
            return Err("ECH поддерживается только с security=tls.".into());
        }
        t["ech"] = ech(e)?;
    }
    if q.contains_key("fp") || security == "reality" {
        let fp = get(q, "fp", "chrome");
        if ![
            "chrome",
            "firefox",
            "edge",
            "safari",
            "360",
            "qq",
            "ios",
            "android",
            "random",
            "randomized",
        ]
        .contains(&fp)
        {
            return Err("TLS fingerprint не поддерживается выбранным ядром.".into());
        }
        t["utls"] = json!({"enabled":true,"fingerprint":fp});
    }
    if security == "reality" {
        let pbk = get(q, "pbk", "");
        if !q.contains_key("sni")
            || pbk.len() != 43
            || URL_SAFE_NO_PAD.decode(pbk).map_or(true, |v| v.len() != 32)
        {
            return Err("Reality требует SNI и 32-байтовый Base64URL public key (pbk).".into());
        }
        let sid = get(q, "sid", "").to_lowercase();
        if sid.len() > 16
            || !sid.len().is_multiple_of(2)
            || !sid.bytes().all(|c| c.is_ascii_hexdigit())
        {
            return Err("Некорректный Reality short ID.".into());
        }
        t["reality"] = json!({"enabled":true,"public_key":pbk,"short_id":sid});
    } else if any(q, REALITY) {
        return Err("Reality-параметры заданы без security=reality.".into());
    }
    Ok(Some(t))
}
fn transport(q: &Query) -> Result<Option<Value>> {
    let kind = get(q, "type", "tcp");
    if matches!(kind, "tcp" | "raw" | "original") {
        if TRANSPORT
            .iter()
            .any(|k| !["type", "headerType"].contains(k) && q.contains_key(*k))
            || get(q, "headerType", "none") != "none"
        {
            return Err("Параметры транспорта несовместимы с обычным TCP.".into());
        }
        return Ok(None);
    }
    if kind == "xhttp" {
        if any(q, &["serviceName", "authority", "headerType", "ed", "eh"]) {
            return Err("Параметры другого транспорта заданы для XHTTP.".into());
        }
        let mut extra: Value = strict_json(get(q, "extra", "{}"))?;
        if !extra.is_object()
            || extra
                .as_object()
                .unwrap()
                .keys()
                .any(|k| !["mode", "xPaddingBytes"].contains(&k.as_str()))
        {
            return Err("XHTTP extra поддерживает mode и xPaddingBytes.".into());
        }
        for (a, b) in [("mode", "mode"), ("x_padding_bytes", "xPaddingBytes")] {
            if let Some(v) = q.get(a) {
                if extra.get(b).is_some_and(|old| old != v) {
                    return Err("Параметры XHTTP противоречат друг другу.".into());
                }
                extra[b] = json!(v);
            }
        }
        let mode = extra
            .as_object_mut()
            .unwrap()
            .remove("mode")
            .unwrap_or(json!("auto"));
        if !["auto", "packet-up", "stream-up", "stream-one"]
            .iter()
            .any(|s| mode == *s)
        {
            return Err("Неподдерживаемый режим XHTTP.".into());
        }
        if let Some(p) = extra.get("xPaddingBytes") {
            let s = p.as_str().ok_or("Некорректный диапазон xPaddingBytes.")?;
            if !Regex::new(r"^[0-9]{1,5}(?:-[0-9]{1,5})?$")
                .unwrap()
                .is_match(s)
            {
                return Err("Некорректный диапазон xPaddingBytes.".into());
            }
            let nums: Vec<u32> = s.split('-').filter_map(|s| s.parse().ok()).collect();
            if s != "0"
                && !(nums[0] >= 1
                    && nums[0] <= *nums.last().unwrap()
                    && *nums.last().unwrap() <= 65536)
            {
                return Err("Некорректный диапазон xPaddingBytes.".into());
            }
        }
        let path = get(q, "path", "/");
        if !path.starts_with('/') {
            return Err("Путь транспорта должен начинаться с /.".into());
        }
        let mut t = json!({"type":"xhttp","path":path,"host":get(q,"host",""),"mode":mode});
        if !extra.as_object().unwrap().is_empty() {
            t["extra"] = extra;
        }
        return Ok(Some(t));
    }
    if !["ws", "grpc", "http", "h2", "httpupgrade"].contains(&kind) {
        return Err(
            "Транспорт не поддерживается: доступны TCP, WS, HTTP, gRPC, HTTPUpgrade и XHTTP."
                .into(),
        );
    }
    if any(q, &["extra", "x_padding_bytes", "headerType"]) {
        return Err("Параметры другого транспорта заданы для этого транспорта.".into());
    }
    if kind == "grpc" {
        if any(q, &["path", "host", "ed", "eh"])
            || !["", "gun", "multi"].contains(&get(q, "mode", "gun"))
        {
            return Err("Некорректные параметры gRPC.".into());
        }
        let a = get(q, "authority", "");
        if !a.is_empty() {
            let u = url::Url::parse(&format!("http://{a}"))
                .map_err(|_| "Некорректный gRPC authority.")?;
            if !a.is_ascii()
                || a.ends_with(':')
                || a.chars().any(char::is_whitespace)
                || u.host_str().is_none()
                || !u.username().is_empty()
                || u.password().is_some()
                || u.path() != "/"
                || u.query().is_some()
                || u.fragment().is_some()
                || a.contains('/')
                || u.port() == Some(0)
            {
                return Err("Некорректный gRPC authority.".into());
            }
            host(u.host_str().unwrap())?;
        }
        return Ok(Some(
            json!({"type":"grpc","service_name":get(q,"serviceName","")}),
        ));
    }
    if any(q, &["serviceName", "authority", "mode"]) {
        return Err("gRPC-параметры заданы для другого транспорта.".into());
    }
    let path = get(q, "path", "/");
    if !path.starts_with('/') {
        return Err("Путь транспорта должен начинаться с /.".into());
    }
    let mut t = json!({"type":if kind=="h2"{"http"}else{kind},"path":path});
    if let Some(h) = q.get("host") {
        if kind == "ws" {
            t["headers"] = json!({"Host":h});
        } else {
            t["host"] = if t["type"] == "http" {
                json!(h.split(',').collect::<Vec<_>>())
            } else {
                json!(h)
            };
        }
    }
    if any(q, &["ed", "eh"]) {
        if kind != "ws" {
            return Err("Early data поддерживается только для WebSocket.".into());
        }
        let ed: u32 = get(q, "ed", "0")
            .parse()
            .map_err(|_| "Некорректный размер WebSocket early data.")?;
        if ed > 65536 {
            return Err("Некорректный размер WebSocket early data.".into());
        }
        t["max_early_data"] = json!(ed);
        t["early_data_header_name"] = json!(get(q, "eh", "Sec-WebSocket-Protocol"));
    }
    Ok(Some(t))
}
fn encryption(s: &str) -> Result<()> {
    if s == "none" {
        return Ok(());
    }
    let parts: Vec<_> = s.split('.').collect();
    let error = "Некорректный VLESS encryption.";
    if parts.len() < 4
        || parts[0] != "mlkem768x25519plus"
        || !["native", "xorpub", "random"].contains(&parts[1])
        || !["0rtt", "1rtt"].contains(&parts[2])
    {
        return Err(error.into());
    }
    let mut started = false;
    let mut total = 0;
    let pattern = Regex::new(r"^[0-9]{1,5}-[0-9]{1,5}-[0-9]{1,5}$").unwrap();
    for (i, p) in parts[3..].iter().enumerate() {
        if !started && pattern.is_match(p) {
            let n: Vec<u32> = p.split('-').map(|s| s.parse().unwrap()).collect();
            if n[0] > 100 || n[1] > n[2] || n[2] > 65553 || (i == 0 && (n[0] != 100 || n[1] < 35)) {
                return Err(error.into());
            }
            if i % 2 == 0 {
                total += n[2];
                if total > 65553 {
                    return Err(error.into());
                }
            }
        } else {
            started = true;
            if ![43, 1579].contains(&p.len())
                || URL_SAFE_NO_PAD
                    .decode(p)
                    .map_or(true, |v| ![32, 1184].contains(&v.len()))
            {
                return Err(error.into());
            }
        }
    }
    if started {
        Ok(())
    } else {
        Err(error.into())
    }
}
pub fn parse_uri(input: &str, source: Option<&str>) -> Result<Profile> {
    let mut uri = input.to_string();
    if Regex::new(r"(?i)^(vless|trojan|hysteria2|hy2)\\://")
        .unwrap()
        .is_match(&uri)
        || uri.contains("(mailto:")
    {
        uri = Regex::new(r"\[([^\[\]]+)\]\(mailto:[^()]*\)")
            .unwrap()
            .replace_all(&uri, "$1")
            .into_owned();
        uri = Regex::new(r"\\([:._])")
            .unwrap()
            .replace_all(&uri, "$1")
            .into_owned();
        uri = Regex::new(r"\s*&#(?:x20|32);\s*$")
            .unwrap()
            .replace_all(&uri, "")
            .trim()
            .trim_end_matches('\\')
            .into();
    }
    if uri.len() > 16384 {
        return Err("Ссылка слишком длинная.".into());
    }
    if uri.chars().any(|c| c.is_control() || c.is_whitespace()) {
        return Err("Пробелы и управляющие символы должны быть percent-encoded.".into());
    }
    // Split the authority ourselves: URL parsing must not rewrite a password's colon.
    let (scheme, rest) = uri.split_once("://").ok_or("Не распознан формат ссылки.")?;
    let scheme = scheme.to_lowercase();
    let kind = if scheme == "hy2" {
        "hysteria2"
    } else {
        scheme.as_str()
    };
    if !["vless", "trojan", "hysteria2"].contains(&kind) {
        return Err("Протокол ссылки пока не поддерживается импортёром.".into());
    }
    let (rest, fragment) = rest.split_once('#').unwrap_or((rest, ""));
    let (authority_path, query) = rest.split_once('?').unwrap_or((rest, ""));
    let (authority, path) = authority_path
        .split_once('/')
        .unwrap_or((authority_path, ""));
    if !path.is_empty() {
        return Err("Путь URI не поддерживается; используйте параметр path.".into());
    }
    let (auth, endpoint) = authority
        .rsplit_once('@')
        .ok_or("Не указан адрес сервера или учётные данные.")?;
    let auth = decode(auth)?;
    if auth.is_empty() {
        return Err("Учётные данные не могут быть пустыми.".into());
    }
    let endpoint_url = url::Url::parse(&format!("http://{endpoint}"))
        .map_err(|_| "Некорректный URI, IPv6 или порт.")?;
    let explicit_port = if endpoint.starts_with('[') {
        endpoint
            .rsplit_once(']')
            .is_some_and(|(_, s)| s.starts_with(':'))
    } else {
        endpoint.contains(':')
    };
    if kind == "vless" && !explicit_port {
        return Err("Для VLESS нужно указать порт.".into());
    }
    let port = if explicit_port {
        endpoint
            .rsplit_once(':')
            .and_then(|(_, s)| s.parse::<u16>().ok())
            .filter(|p| *p > 0)
            .ok_or("Некорректный порт сервера.")?
    } else {
        443
    };
    let server = host(endpoint_url.host_str().ok_or("Не указан адрес сервера.")?)?;
    let mut q = Query::new();
    if !query.is_empty() {
        for item in query.split('&') {
            let (k, v) = item.split_once('=').ok_or("Некорректный query-параметр.")?;
            let k = decode(k)?;
            if k.is_empty() || q.insert(k, decode(v)?).is_some() {
                return Err("Некорректный или повторяющийся query-параметр.".into());
            }
        }
    }
    let mut allowed: HashSet<&str> = TLS.iter().copied().collect();
    allowed.insert("security");
    if kind == "hysteria2" {
        allowed.extend(["obfs", "obfs-password"]);
    } else {
        allowed.extend(TRANSPORT);
        allowed.extend(REALITY);
        if kind == "vless" {
            allowed.extend(["encryption", "flow", "packetEncoding"]);
        }
    }
    if q.keys().any(|s| !allowed.contains(s.as_str())) {
        return Err(
            "Неизвестный query-параметр; профиль отклонён без изменения его смысла.".into(),
        );
    }
    let mut out = json!({"type":kind,"server":server,"server_port":port});
    let mut options = json!({});
    if kind == "vless" {
        out["uuid"] = json!(uuid::Uuid::parse_str(&auth)
            .map_err(|_| "Некорректный UUID VLESS.")?
            .to_string());
        let enc = get(&q, "encryption", "none");
        encryption(enc)?;
        if enc != "none" {
            options["encryption"] = json!(enc);
        }
        let flow = get(&q, "flow", "");
        if !["", "xtls-rprx-vision"].contains(&flow) {
            return Err("Поддерживается только flow=xtls-rprx-vision.".into());
        }
        if !flow.is_empty() {
            if enc == "none"
                && (get(&q, "security", "none") == "none"
                    || !["tcp", "raw", "original"].contains(&get(&q, "type", "tcp")))
            {
                return Err(
                    "Vision требует VLESS encryption либо TLS/Reality с обычным TCP.".into(),
                );
            }
            out["flow"] = json!(flow);
        }
        if let Some(p) = q.get("packetEncoding") {
            if !["xudp", "packetaddr"].contains(&p.as_str()) {
                return Err("Неподдерживаемый packetEncoding.".into());
            }
            out["packet_encoding"] = json!(p);
        }
    } else {
        out["password"] = json!(auth);
    }
    let mut t = tls(
        &q,
        &server,
        get(&q, "security", if kind == "vless" { "none" } else { "tls" }),
    )?;
    if kind == "hysteria2" {
        if get(&q, "security", "tls") != "tls" {
            return Err("Hysteria2 требует security=tls.".into());
        }
        if let Some(t) = t.as_mut() {
            t.as_object_mut().unwrap().remove("utls");
        }
        if let Some(fp) = q.get("fp") {
            options["fp"] = json!(fp);
        }
        if let Some(o) = q.get("obfs") {
            if o != "salamander" || get(&q, "obfs-password", "").is_empty() {
                return Err("Поддерживается obfs=salamander с непустым obfs-password.".into());
            }
            out["obfs"] = json!({"type":"salamander","password":q["obfs-password"]});
        } else if q.contains_key("obfs-password") {
            return Err("obfs-password указан без obfs.".into());
        }
    } else {
        if kind == "trojan" && (t.is_none() || get(&q, "type", "tcp") == "xhttp") {
            return Err("Trojan требует TLS или Reality; XHTTP доступен для VLESS.".into());
        }
        if let Some(tr) = transport(&q)? {
            if tr["type"] == "grpc" {
                if t.as_ref()
                    .and_then(|t| t["alpn"].as_array())
                    .is_some_and(|a| !a.iter().any(|v| v == "h2"))
                {
                    return Err("gRPC требует HTTP/2: ALPN должен включать h2.".into());
                }
                if get(&q, "mode", "") == "multi" {
                    options["grpc_mode"] = json!("multi");
                }
                if !get(&q, "authority", "").is_empty() {
                    options["grpc_authority"] = json!(q["authority"]);
                }
            }
            out["transport"] = tr;
        }
        if let Some(spx) = q.get("spx") {
            if !spx.starts_with('/') {
                return Err("Reality spiderX должен начинаться с /.".into());
            }
            options["spx"] = json!(spx);
        }
        if let Some(v) = q.get("support-x25519mlkem768") {
            options["support-x25519mlkem768"] = json!(boolean(v)?);
        }
    }
    if let Some(t) = t {
        out["tls"] = t;
    }
    let name = if fragment.is_empty() {
        format!("{} · {}", kind.to_uppercase(), server)
    } else {
        decode(fragment)?
    };
    let profile = Profile {
        name: name.chars().take(180).collect(),
        outbound: out,
        source_id: source.map(str::to_owned),
        options,
    };
    if profile.requires_xray() {
        crate::config::xray(&profile, 1080, "validation", &Default::default(), None)?;
    }
    Ok(profile)
}

// Reject duplicate JSON keys recursively, including XHTTP extra.
pub fn strict_json(text: &str) -> Result<Value> {
    use serde::de::{self, MapAccess, SeqAccess, Visitor};
    struct Strict(Value);
    impl<'de> serde::Deserialize<'de> for Strict {
        fn deserialize<D: serde::Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
            struct V;
            impl<'de> Visitor<'de> for V {
                type Value = Strict;
                fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                    f.write_str("JSON без повторяющихся ключей")
                }
                fn visit_map<M: MapAccess<'de>>(
                    self,
                    mut m: M,
                ) -> std::result::Result<Strict, M::Error> {
                    let mut v = serde_json::Map::new();
                    while let Some((k, Strict(x))) = m.next_entry::<String, Strict>()? {
                        if v.insert(k, x).is_some() {
                            return Err(de::Error::custom("duplicate key"));
                        }
                    }
                    Ok(Strict(Value::Object(v)))
                }
                fn visit_seq<S: SeqAccess<'de>>(
                    self,
                    mut s: S,
                ) -> std::result::Result<Strict, S::Error> {
                    let mut v = Vec::new();
                    while let Some(Strict(x)) = s.next_element()? {
                        v.push(x);
                    }
                    Ok(Strict(Value::Array(v)))
                }
                fn visit_str<E: de::Error>(self, s: &str) -> std::result::Result<Strict, E> {
                    Ok(Strict(json!(s)))
                }
                fn visit_bool<E: de::Error>(self, b: bool) -> std::result::Result<Strict, E> {
                    Ok(Strict(json!(b)))
                }
                fn visit_i64<E: de::Error>(self, n: i64) -> std::result::Result<Strict, E> {
                    Ok(Strict(json!(n)))
                }
                fn visit_u64<E: de::Error>(self, n: u64) -> std::result::Result<Strict, E> {
                    Ok(Strict(json!(n)))
                }
                fn visit_f64<E: de::Error>(self, n: f64) -> std::result::Result<Strict, E> {
                    Ok(Strict(json!(n)))
                }
                fn visit_unit<E: de::Error>(self) -> std::result::Result<Strict, E> {
                    Ok(Strict(Value::Null))
                }
            }
            d.deserialize_any(V)
        }
    }
    serde_json::from_str::<Strict>(text)
        .map(|v| v.0)
        .map_err(|_| "Некорректный JSON или повторяющиеся поля.".into())
}
pub fn parse_subscription(body: &[u8], source: Option<&str>) -> Result<ImportReport> {
    if body.len() > MAX_BODY {
        return Err("Подписка превышает лимит 2 МиБ.".into());
    }
    let mut text = std::str::from_utf8(body)
        .map_err(|_| "Подписка не является UTF-8 текстом.")?
        .trim_start_matches('\u{feff}')
        .trim()
        .to_string();
    if text.is_empty() {
        return Err("Подписка пуста. Предыдущие серверы сохранены.".into());
    }
    if text.starts_with(['<', '{', '['])
        || Regex::new(r"(?i)^(proxies|proxy-groups|mixed-port):")
            .unwrap()
            .is_match(&text)
    {
        return Err("HTML, Clash YAML и удалённый sing-box JSON не поддерживаются.".into());
    }
    if !text.contains("://") && !text.contains("\\://") {
        text = String::from_utf8(unbase64(
            &text
                .chars()
                .filter(|c| !c.is_whitespace())
                .collect::<String>(),
        )?)
        .map_err(|_| "Некорректный UTF-8 в Base64.")?;
    }
    if text.lines().count() > 10000 {
        return Err("Подписка содержит больше 10000 строк.".into());
    }
    let mut report = ImportReport::default();
    let mut seen = HashSet::new();
    for (i, line) in text.trim_start_matches('\u{feff}').lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        match parse_uri(line, source) {
            Ok(p) => {
                if seen.insert(p.identity()) {
                    report.profiles.push(p);
                } else {
                    report.duplicates += 1;
                }
            }
            Err(reason) => report.rejected.push(Rejection {
                line: i + 1,
                reason,
            }),
        }
    }
    Ok(report)
}
pub fn import(text: &str) -> Result<ImportReport> {
    if text.len() > MAX_BODY {
        return Err("Данные импорта слишком большие.".into());
    }
    if text.trim_start().starts_with('{') {
        let v = strict_json(text)?;
        if v.as_object().is_none_or(|m| m.len() != 2) || v["version"] != 1 || !v["links"].is_array()
        {
            return Err(
                "Локальный JSON должен иметь формат {\"version\":1,\"links\":[\"vless://…\"]}."
                    .into(),
            );
        }
        let links = v["links"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| {
                v.as_str()
                    .filter(|s| !s.contains(['\n', '\r']))
                    .ok_or("Некорректная ссылка в JSON.")
            })
            .collect::<std::result::Result<Vec<_>, _>>()?;
        parse_subscription(links.join("\n").as_bytes(), None)
    } else {
        parse_subscription(text.as_bytes(), None)
    }
}
