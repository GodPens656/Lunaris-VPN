use crate::Result;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct Profile {
    pub name: String,
    pub outbound: Value,
    #[serde(default)]
    pub source_id: Option<String>,
    #[serde(default = "object")]
    pub options: Value,
}
pub fn object() -> Value {
    json!({})
}
impl Profile {
    pub fn identity(&self) -> String {
        // serde_json's sorted maps match Python's sort_keys canonical format.
        let mut value = self.outbound.clone();
        if let Some(map) = value.as_object_mut() {
            map.remove("tag");
            if self.options.as_object().is_some_and(|v| !v.is_empty()) {
                map.insert("share_options".into(), self.options.clone());
            }
        }
        format!(
            "{:x}",
            Sha256::digest(serde_json::to_vec(&value).unwrap_or_default())
        )
    }
    pub fn key(&self) -> String {
        format!(
            "{}:{}",
            self.source_id.as_deref().unwrap_or("manual"),
            self.identity()
        )
    }
    pub fn protocol(&self) -> &str {
        self.outbound["type"].as_str().unwrap_or("")
    }
    pub fn xray_grpc(&self) -> bool {
        self.outbound["transport"]["type"] == "grpc"
            && (self.options["grpc_mode"] == "multi"
                || self.options["grpc_authority"]
                    .as_str()
                    .is_some_and(|s| !s.is_empty()))
    }
    pub fn requires_xray(&self) -> bool {
        matches!(self.protocol(), "vless" | "trojan")
            && (self.outbound["transport"]["type"] == "xhttp"
                || self.xray_grpc()
                || self.options.get("spx").is_some()
                || self.options.get("support-x25519mlkem768").is_some()
                || self.options["encryption"]
                    .as_str()
                    .is_some_and(|s| s != "none"))
    }
}

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct Settings {
    pub mode: String,
    pub mixed_port: u16,
    pub api_port: u16,
    pub dns_server: String,
    pub dns_tls_name: String,
    pub dns_kind: String,
    pub bootstrap_dns: String,
    pub ipv6: bool,
    pub update_on_start: bool,
    pub update_minutes: u32,
    pub probe_url: String,
    pub verify_connection: bool,
    pub latency_method: String,
    pub auto_sort_ping: bool,
    pub minimize_to_tray: bool,
    pub close_to_tray: bool,
    pub core_path: String,
    pub core: String,
    pub mihomo_path: String,
    pub bypass_russian_domains: bool,
    pub bypass_domains: Vec<String>,
}
impl Default for Settings {
    fn default() -> Self {
        Self {
            mode: "proxy".into(),
            mixed_port: 2080,
            api_port: 2081,
            dns_server: "1.1.1.1".into(),
            dns_tls_name: "cloudflare-dns.com".into(),
            dns_kind: "https".into(),
            bootstrap_dns: "1.1.1.1".into(),
            ipv6: true,
            update_on_start: true,
            update_minutes: 360,
            probe_url: "https://www.gstatic.com/generate_204".into(),
            verify_connection: true,
            latency_method: "proxy".into(),
            auto_sort_ping: true,
            minimize_to_tray: true,
            close_to_tray: true,
            core_path: String::new(),
            core: "sing-box".into(),
            mihomo_path: String::new(),
            bypass_russian_domains: false,
            bypass_domains: Vec::new(),
        }
    }
}
impl Settings {
    pub fn normalized_bypass_domains(&self) -> Result<Vec<String>> {
        let mut domains = Vec::new();
        for value in &self.bypass_domains {
            let raw = value.trim();
            let invalid = || {
                format!("Некорректный домен «{value}». Введите домен без ссылки, пути, порта и маски, например example.com.")
            };
            if raw.is_empty()
                || raw.chars().any(|c| {
                    c.is_whitespace() || c.is_control() || "/\\:@?#%*[],;".contains(c)
                })
            {
                return Err(invalid());
            }
            let url::Host::Domain(domain) = url::Host::parse(raw).map_err(|_| invalid())? else {
                return Err(invalid());
            };
            let domain = domain.strip_suffix('.').unwrap_or(&domain);
            if domain.len() > 253
                || !domain.contains('.')
                || domain.split('.').any(|label| {
                    label.is_empty()
                        || label.len() > 63
                        || label.starts_with('-')
                        || label.ends_with('-')
                        || !label.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'-')
                })
            {
                return Err(invalid());
            }
            if !domains.iter().any(|existing| existing == domain) {
                domains.push(domain.to_string());
            }
        }
        Ok(domains)
    }

    pub fn validate(&self) -> Result<()> {
        if !matches!(self.core.as_str(), "sing-box" | "mihomo") {
            return Err("Неизвестное ядро подключения.".into());
        }
        if !matches!(self.mode.as_str(), "proxy" | "tun") {
            return Err("Неизвестный режим подключения.".into());
        }
        if !matches!(self.latency_method.as_str(), "tcp" | "icmp" | "proxy") {
            return Err("Неизвестный метод измерения.".into());
        }
        if self.mixed_port < 1024 || self.api_port < 1024 || self.mixed_port == self.api_port {
            return Err("Локальные порты должны различаться и быть в диапазоне 1024–65535.".into());
        }
        if self.dns_server.parse::<std::net::IpAddr>().is_err()
            || self.bootstrap_dns.parse::<std::net::IpAddr>().is_err()
        {
            return Err("Для DNS нужен IP-адрес, чтобы избежать циклического разрешения.".into());
        }
        if !matches!(self.dns_kind.as_str(), "https" | "tls" | "udp") {
            return Err("Выберите HTTPS, TLS или UDP DNS.".into());
        }
        if self.dns_kind != "udp"
            && (self.dns_tls_name.is_empty()
                || self
                    .dns_tls_name
                    .chars()
                    .any(|c| c.is_whitespace() || c.is_control() || "/:".contains(c)))
        {
            return Err("Введите корректное TLS-имя DNS-сервера.".into());
        }
        if self.update_minutes > 10080 {
            return Err("Интервал обновления: 0 (выключено) или 1–10080 минут.".into());
        }
        let url =
            url::Url::parse(&self.probe_url).map_err(|_| "Некорректный адрес HTTPS-проверки.")?;
        if url.scheme() != "https"
            || url.host_str().is_none()
            || !url.username().is_empty()
            || url.password().is_some()
        {
            return Err(
                "Адрес проверки соединения должен быть HTTPS URL без учётных данных.".into(),
            );
        }
        self.normalized_bypass_domains()?;
        Ok(())
    }
}

#[derive(Clone, Default, Serialize, Deserialize, Debug)]
pub struct Subscription {
    pub id: String,
    pub name: String,
    pub url: String,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub last_success: Option<f64>,
    #[serde(default)]
    pub error: Option<String>,
    #[serde(default = "object")]
    pub userinfo: Value,
    #[serde(default)]
    pub rejected: Vec<Rejection>,
    #[serde(default)]
    pub duplicates: usize,
    #[serde(default)]
    pub auto_name: bool,
}
#[derive(Clone, Default, Serialize, Deserialize, Debug)]
pub struct State {
    #[serde(default)]
    pub profiles: Vec<Profile>,
    #[serde(default)]
    pub subscriptions: Vec<Subscription>,
    #[serde(default)]
    pub selected: Option<String>,
    #[serde(default)]
    pub settings: Settings,
}
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct Rejection {
    pub line: usize,
    pub reason: String,
}
#[derive(Default, Serialize, Deserialize, Debug)]
pub struct ImportReport {
    pub profiles: Vec<Profile>,
    pub rejected: Vec<Rejection>,
    pub duplicates: usize,
}
#[derive(Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct Stats {
    pub upload: u64,
    pub download: u64,
    pub duration: u64,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct CoreState {
    pub status: String,
    pub error: Option<String>,
    #[serde(flatten)]
    pub stats: Stats,
}
impl Default for CoreState {
    fn default() -> Self {
        Self {
            status: "disconnected".into(),
            error: None,
            stats: Stats::default(),
        }
    }
}
pub fn timestamp() -> f64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs_f64()
}
