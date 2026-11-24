use async_trait::async_trait;
use lunaris_backend::{
    config,
    engine::{Engine, Host},
    latency,
    models::*,
    parser,
    redaction::SafeLog,
    storage::Repository,
    subscriptions, Result,
};
use serde_json::json;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, Mutex,
};

#[derive(Default)]
struct Fake {
    state: Mutex<CoreState>,
    fail: AtomicBool,
    starts: Mutex<Vec<String>>,
    stop: tokio::sync::Notify,
    wait_stop: AtomicBool,
}
#[async_trait]
impl Host for Fake {
    async fn encrypt(&self, data: &[u8]) -> Result<Vec<u8>> {
        if self.fail.load(Ordering::SeqCst) {
            return Err("vault failed".into());
        }
        Ok(data.iter().map(|b| b ^ 0xa5).collect())
    }
    async fn decrypt(&self, data: &[u8]) -> Result<Vec<u8>> {
        Ok(data.iter().map(|b| b ^ 0xa5).collect())
    }
    async fn connect(&self, p: &Profile, _: &Settings) -> Result<CoreState> {
        self.starts.lock().unwrap().push(p.key());
        let s = CoreState {
            status: "connected".into(),
            ..Default::default()
        };
        *self.state.lock().unwrap() = s.clone();
        Ok(s)
    }
    async fn disconnect(&self) -> Result<CoreState> {
        if self.wait_stop.load(Ordering::SeqCst) {
            self.stop.notified().await;
        }
        *self.state.lock().unwrap() = CoreState::default();
        Ok(CoreState::default())
    }
    async fn snapshot(&self) -> Result<CoreState> {
        Ok(self.state.lock().unwrap().clone())
    }
}
fn uri() -> &'static str {
    "vless://11111111-1111-4111-8111-111111111111@example.com:443?security=tls&type=grpc&serviceName=test"
}
#[test]
fn import_preserves_password_plus_ipv6_and_rejects_unknown() {
    let p = parser::parse_uri(
        "trojan://p%40ss%3Aword+plus@[2001:db8::1]?type=ws&path=%2Fv%3Fed%3D5#Name+Plus",
        None,
    )
    .unwrap();
    assert_eq!(p.outbound["password"], "p@ss:word+plus");
    assert_eq!(p.outbound["server"], "2001:db8::1");
    assert_eq!(p.name, "Name+Plus");
    for suffix in [
        "&foo=secret",
        "&mode=wrong",
        "&authority=user%40example.com",
        "&authority=example.com%3A0",
        "&alpn=http%2F1.1",
    ] {
        assert!(parser::parse_uri(&format!("{}{suffix}", uri()), None).is_err());
    }
}
#[test]
fn identity_and_grpc_options_survive_roundtrip() {
    let a = parser::parse_uri(uri(), Some("source")).unwrap();
    let b = parser::parse_uri(&format!("{}#other", uri()), Some("source")).unwrap();
    assert_eq!(a.key(), b.key());
    let ext = parser::parse_uri(
        &format!("{}&mode=multi&authority=cdn.example.com", uri()),
        None,
    )
    .unwrap();
    assert!(ext.requires_xray());
    assert_ne!(a.identity(), ext.identity());
    let restored: Profile = serde_json::from_value(serde_json::to_value(&ext).unwrap()).unwrap();
    assert_eq!(restored.identity(), ext.identity());
    let c = config::xray(&ext, 1080, "local", &Settings::default(), None).unwrap();
    assert_eq!(
        c["outbounds"][0]["streamSettings"]["grpcSettings"],
        json!({"serviceName":"test","multiMode":true,"authority":"cdn.example.com"})
    );
}
#[test]
fn strict_json_rejects_duplicates_and_import_limits() {
    for s in [r#"{"a":1,"a":2}"#, r#"{"a":{"x":1,"x":2}}"#] {
        assert!(parser::strict_json(s).is_err());
    }
    let s = format!("{}\n{}#rename\ninvalid", uri(), uri());
    let r = parser::parse_subscription(s.as_bytes(), None).unwrap();
    assert_eq!(r.profiles.len(), 1);
    assert_eq!(r.duplicates, 1);
    assert_eq!(r.rejected[0].line, 3);
    assert!(parser::import(&"x".repeat(parser::MAX_BODY + 1)).is_err());
}
#[test]
fn mihomo_reality_preserves_firefox_with_hybrid_key_exchange() {
    let link = "vless\\://11111111-1111-4111-8111-111111111111@example.com:5555?encryption=none&fp=firefox&pbk=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA&security=reality&sid=a2&sni=example.net&spx=%2Fsynthetic&support-x25519mlkem768=true&type=tcp";
    let settings = Settings {
        core: "mihomo".into(),
        ..Default::default()
    };
    for (fingerprint, expected) in [("firefox", "firefox"), ("ios", "chrome")] {
        let link = link.replace("fp=firefox", &format!("fp={fingerprint}"));
        let profile = parser::parse_uri(&link, None).unwrap();
        let windows = config::mihomo(&profile, &settings, "api", None).unwrap();
        let android = config::android(&profile, &settings, "api", "local").unwrap();
        let proxy = &windows["proxies"][0];
        assert_eq!(proxy, &android["sever_mihomo"]["proxies"][0]);
        assert_eq!(proxy["client-fingerprint"], expected);
        assert_eq!(proxy["reality-opts"]["support-x25519mlkem768"], true);
        assert_eq!(proxy["reality-opts"]["short-id"], "a2");
        assert!(proxy.get("encryption").is_none());
        assert_eq!(profile.options["spx"], "/synthetic");
    }
}
#[test]
fn android_sidecars_use_local_binding_gvisor_and_routing() {
    let p = parser::parse_uri(&format!("{}&mode=multi", uri()), None).unwrap();
    let settings = Settings {
        core: "mihomo".into(),
        bypass_russian_domains: true,
        ..Default::default()
    };
    let c = config::android(&p, &settings, "api", "secret").unwrap();
    assert!(c.get("sever_xray").is_some());
    assert!(c.get("sever_mihomo").is_none());
    assert_eq!(c["outbounds"][0]["inet4_bind_address"], "127.0.0.1");
    assert_eq!(c["inbounds"][1]["stack"], "gvisor");
    assert_eq!(c["dns"]["servers"][1]["detour"], "proxy");
    assert_eq!(
        c["route"]["rules"][2]["domain_suffix"],
        json!(["xn--p1ai", "su", "ru"])
    );
    assert_eq!(settings.core, "mihomo");
}

#[test]
fn android_proxy_probes_authenticate_and_route_through_the_candidate() {
    let profile = parser::parse_uri(uri(), None).unwrap();
    let mut settings = Settings {
        mode: "tun".into(),
        bypass_russian_domains: true,
        bypass_domains: vec!["example.com".into()],
        ..Default::default()
    };
    let sing = config::android_proxy_probe(&profile, &settings, "api", "probe-secret").unwrap();
    assert_eq!(sing["inbounds"].as_array().unwrap().len(), 1);
    let inbound = &sing["inbounds"][0];
    assert_eq!(inbound["type"], "mixed");
    assert_eq!(inbound["listen"], "127.0.0.1");
    assert_eq!(inbound["listen_port"], settings.mixed_port);
    assert_eq!(
        inbound["users"],
        json!([{"username":"lunaris","password":"probe-secret"}])
    );
    assert_eq!(sing["outbounds"][0]["inet4_bind_address"], "127.0.0.1");
    assert_eq!(sing["route"]["final"], "proxy");
    assert_eq!(sing["route"]["rules"].as_array().unwrap().len(), 2);

    settings.core = "mihomo".into();
    let config = config::android_proxy_probe(&profile, &settings, "api", "probe-secret").unwrap();
    let mihomo = &config["sever_mihomo"];
    assert_eq!(mihomo["tun"]["enable"], false);
    assert_eq!(mihomo["mixed-port"], settings.mixed_port);
    assert_eq!(mihomo["authentication"], json!(["lunaris:probe-secret"]));
    assert_eq!(mihomo["rules"], json!(["MATCH,proxy"]));
}

#[test]
fn custom_bypass_domains_normalize_idna_and_reject_non_domains() {
    let old: Settings = serde_json::from_value(json!({})).unwrap();
    assert!(old.bypass_domains.is_empty());
    let mut settings = Settings {
        bypass_domains: vec![
            " Example.COM. ".into(),
            "пример.рф".into(),
            "example.com".into(),
            "xn--e1afmkfd.xn--p1ai".into(),
        ],
        ..Default::default()
    };
    assert_eq!(
        settings.normalized_bypass_domains().unwrap(),
        vec!["example.com", "xn--e1afmkfd.xn--p1ai"]
    );
    for domain in [
        "",
        "https://example.com",
        "example.com/path",
        "example.com:443",
        "*.example.com",
        ".example.com",
        "example..com",
        "example.com..",
        "example.com,other.com",
        "example.com;DIRECT",
        "user@example.com",
        "127.0.0.1",
        "[::1]",
        "localhost",
        "bad_domain.com",
        "-bad.com",
        "bad-.com",
        "bad domain.com",
        "example.com\nother.com",
        "%65xample.com",
    ] {
        settings.bypass_domains = vec![domain.into()];
        assert!(settings.validate().is_err(), "accepted {domain:?}");
    }
    for domain in [
        format!("{}.com", "x".repeat(64)),
        format!("{}.com", "abcd.".repeat(51)),
    ] {
        settings.bypass_domains = vec![domain];
        assert!(settings.validate().is_err());
    }
}

#[test]
fn custom_bypass_routes_work_alone_and_with_russian_zones_on_both_platforms() {
    let profile = parser::parse_uri(uri(), None).unwrap();
    for russian in [false, true] {
        for core in ["sing-box", "mihomo"] {
            let settings = Settings {
                core: core.into(),
                bypass_russian_domains: russian,
                bypass_domains: vec!["Example.COM".into(), "пример.рф".into()],
                ..Default::default()
            };
            let mut expected = if russian {
                vec!["xn--p1ai", "su", "ru"]
            } else {
                vec![]
            };
            expected.extend(["example.com", "xn--e1afmkfd.xn--p1ai"]);
            let sing = config::sing_box(&profile, &settings, "api", false, None, None).unwrap();
            let android = config::android(&profile, &settings, "api", "local").unwrap();
            let xray = parser::parse_uri(&format!("{}&mode=multi", uri()), None).unwrap();
            let bridge = config::android(&xray, &settings, "api", "local").unwrap();
            let mut sing_box_configs = vec![&sing, &bridge];
            if core == "sing-box" {
                sing_box_configs.push(&android);
            }
            for config in sing_box_configs {
                assert_eq!(
                    config["route"]["rules"][2]["domain_suffix"],
                    json!(expected)
                );
                assert_eq!(config["route"]["rules"][2]["outbound"], "direct");
                assert_eq!(config["route"]["final"], "proxy");
                assert_eq!(config["outbounds"][1]["domain_resolver"], "remote");
                assert_eq!(config["dns"]["servers"][1]["detour"], "proxy");
            }
            let mihomo = config::mihomo(&profile, &settings, "api", None).unwrap();
            let mut rules: Vec<_> = expected
                .iter()
                .map(|s| format!("DOMAIN-SUFFIX,{s},DIRECT"))
                .collect();
            rules.push("MATCH,proxy".into());
            assert_eq!(mihomo["rules"], json!(rules));
            assert_eq!(mihomo["sniffer"]["enable"], true);
            if core == "mihomo" {
                assert_eq!(android["sever_mihomo"]["rules"], json!(rules));
                assert_eq!(android["sever_mihomo"]["secret"], "api");
                assert!(android.get("outbounds").is_none());
            }
        }
    }
    let settings = Settings::default();
    let sing = config::sing_box(&profile, &settings, "api", false, None, None).unwrap();
    assert_eq!(sing["route"]["rules"].as_array().unwrap().len(), 2);
    let mihomo = config::mihomo(&profile, &settings, "api", None).unwrap();
    assert_eq!(mihomo["rules"], json!(["MATCH,proxy"]));
    assert!(mihomo.get("sniffer").is_none());
}

#[cfg(windows)]
#[tokio::test]
#[ignore = "requires the pinned Windows core binaries in assets/core"]
async fn bundled_cores_start_report_traffic_and_release_ports() {
    use lunaris_backend::windows::{free_port, WindowsHost};

    let assets = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../assets");
    let profile = parser::parse_uri(
        "vless://b87a2fde-5f5a-458a-baad-f9c179530af1@127.0.0.1:65432",
        None,
    )
    .unwrap();
    let directory = tempfile::tempdir().unwrap();
    for core in ["mihomo", "sing-box", "xray"] {
        let log = Arc::new(std::sync::Mutex::new(Default::default()));
        let host =
            WindowsHost::isolated_probe(directory.path().join(core), assets.clone(), log.clone());
        let mixed_port = free_port(&[]).unwrap();
        let settings = Settings {
            core: core.into(),
            mixed_port,
            api_port: free_port(&[mixed_port]).unwrap(),
            verify_connection: false,
            ..Default::default()
        };
        let state = host
            .connect(&profile, &settings)
            .await
            .unwrap_or_else(|e| panic!("{core}: {e}\n{:?}", log.lock().unwrap().lines));
        assert_eq!(state.status, "connected");
        let state = host.snapshot().await.unwrap();
        assert_eq!(state.status, "connected", "{core}: {:?}", state.error);
        assert_eq!(host.disconnect().await.unwrap().status, "disconnected");
        assert!(std::net::TcpListener::bind(("127.0.0.1", mixed_port)).is_ok());
    }
}

#[tokio::test]
async fn custom_bypass_settings_persist_rollback_and_clear() {
    let dir = tempfile::tempdir().unwrap();
    let host = Arc::new(Fake::default());
    let engine = Engine::new(
        dir.path().into(),
        host.clone(),
        Arc::new(Mutex::new(Default::default())),
    )
    .await
    .unwrap();
    engine
        .dispatch(
            "settings",
            json!({"bypass_domains":["Example.COM.","пример.рф","example.com"]}),
        )
        .await
        .unwrap();
    let saved = engine.snapshot().await["settings"].clone();
    assert_eq!(
        saved["bypass_domains"],
        json!(["example.com", "xn--e1afmkfd.xn--p1ai"])
    );
    for patch in [
        json!({"bypass_domains":"example.com"}),
        json!({"bypass_domains":[1]}),
        json!({"bypass_domains":null}),
        json!({"bypass_domains":["valid.com","https://invalid.com"]}),
    ] {
        assert!(engine.dispatch("settings", patch).await.is_err());
        assert_eq!(engine.snapshot().await["settings"], saved);
    }
    host.fail.store(true, Ordering::SeqCst);
    assert!(engine
        .dispatch("settings", json!({"bypass_domains":[]}))
        .await
        .is_err());
    assert_eq!(engine.snapshot().await["settings"], saved);
    host.fail.store(false, Ordering::SeqCst);
    engine.shutdown().await.unwrap();
    drop(engine);
    let repo = Repository::open(dir.path().into(), host.clone())
        .await
        .unwrap();
    assert_eq!(serde_json::to_value(&repo.state.settings).unwrap(), saved);
    drop(repo);
    let engine = Engine::new(
        dir.path().into(),
        host.clone(),
        Arc::new(Mutex::new(Default::default())),
    )
    .await
    .unwrap();
    engine
        .dispatch("settings", json!({"bypass_domains":[]}))
        .await
        .unwrap();
    engine.shutdown().await.unwrap();
    drop(engine);
    let repo = Repository::open(dir.path().into(), host).await.unwrap();
    assert!(repo.state.settings.bypass_domains.is_empty());
}
#[test]
fn replacement_requires_unique_logical_server() {
    let p = parser::parse_uri("trojan://old@example.com#One", Some("source")).unwrap();
    let n = parser::parse_uri("trojan://new@example.com#One", Some("source")).unwrap();
    assert_eq!(
        subscriptions::replacement(&p, std::slice::from_ref(&p), std::slice::from_ref(&n)),
        Some(n.key())
    );
    let duplicate = vec![n.clone(), n];
    assert!(subscriptions::replacement(&p, &[p.clone(), p.clone()], &duplicate).is_none());
}
#[test]
fn links_keep_signed_tokens_and_logs_hide_credentials() {
    let url = "https://sub.example/token%2F?a=%26%2B";
    assert_eq!(
        subscriptions::subscription_url(&format!("lunaris://import://{url}")).unwrap(),
        url
    );
    assert!(subscriptions::validate_url("https://user:secret@x.com").is_err());
    let mut log = SafeLog::default();
    log.register(&json!({"password":"synthetic-password","uuid":"synthetic-id"}));
    log.add("synthetic-password https://sub.example/token");
    let text = log.lines.back().unwrap();
    assert!(!text.contains("synthetic-password") && !text.contains("sub.example"));
    for _ in 0..500 {
        log.add("line");
    }
    assert_eq!(log.lines.len(), 300);
}
#[test]
fn quic_probe_and_salamander_are_bounded() {
    let packet =
        latency::initial(&[0, 1, 2, 3, 4, 5, 6, 7], &[8, 9, 10, 11, 12, 13, 14, 15]).unwrap();
    assert_eq!(packet.len(), 1200);
    assert!(!latency::is_reply(&packet, &[0; 8], &[1; 8]));
    for n in 0..128 {
        assert!(!latency::is_reply(&vec![0xff; n], &[0; 8], &[1; 8]));
    }
    let encoded = latency::salamander(&packet, "secret", &[7; 8]);
    assert_eq!(latency::salamander(&encoded, "secret", &[7; 8]), packet);
}

#[test]
fn quic_rfc9001_reply_vectors_verify_integrity() {
    let unhex = |s: &str| {
        s.as_bytes()
            .chunks(2)
            .map(|p| u8::from_str_radix(std::str::from_utf8(p).unwrap(), 16).unwrap())
            .collect::<Vec<_>>()
    };
    let destination = unhex("8394c8f03e515708");
    for vector in ["cf000000010008f067a5502a4262b5004075c0d95a482cd0991cd25b0aac406a5816b6394100f37a1c69797554780bb38cc5a99f5ede4cf73c3ec2493a1839b3dbcba3f6ea46c5b7684df3548e7ddeb9c3bf9c73cc3f3bded74b562bfb19fb84022f8ef4cdd93795d77d06edbb7aaf2f58891850abbdca3d20398c276456cbc42158407dd074ee","ff000000010008f067a5502a4262b5746f6b656e04a265ba2eff4d829058fb3f0f2496ba"]{
        let mut packet=unhex(vector);assert!(latency::is_reply(&packet,&destination,&[]));assert!(!latency::is_reply(&packet,b"wrong-id",&[]));for n in 0..packet.len(){assert!(!latency::is_reply(&packet[..n],&destination,&[]));}*packet.last_mut().unwrap()^=1;assert!(!latency::is_reply(&packet,&destination,&[]));
    }
}

#[test]
fn bootstrap_dns_checks_question_and_compressed_answer() {
    let mut packet = vec![0x12, 0x34, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0];
    packet.extend(b"\x07example\x03com\0\0\x01\0\x01");
    packet.extend([0xc0, 12, 0, 1, 0, 1, 0, 0, 0, 30, 0, 4, 127, 0, 0, 1]);
    let parse =
        |data: &[u8], id| lunaris_backend::bootstrap::parse_response(data, id, "example.com", 1);
    assert_eq!(
        parse(&packet, 0x1234).unwrap(),
        vec!["127.0.0.1".parse::<std::net::IpAddr>().unwrap()]
    );
    assert!(parse(&packet, 0).is_none());
    assert!(lunaris_backend::bootstrap::parse_response(&packet, 0x1234, "other.com", 1).is_none());
    for n in 0..packet.len() {
        assert!(parse(&packet[..n], 0x1234).is_none());
    }
}
#[tokio::test]
async fn vault_is_atomic_and_detects_concurrent_access() {
    let dir = tempfile::tempdir().unwrap();
    let host = Arc::new(Fake::default());
    let mut repo = Repository::open(dir.path().into(), host.clone())
        .await
        .unwrap();
    let mut state = State::default();
    state
        .profiles
        .push(parser::parse_uri("trojan://private-password@example.com", None).unwrap());
    repo.commit(state.clone()).await.unwrap();
    let before = std::fs::read(dir.path().join("state.enc")).unwrap();
    assert!(before.starts_with(b"SEVER2\0"));
    assert!(!String::from_utf8_lossy(&before).contains("private-password"));
    assert!(Repository::open(dir.path().into(), host.clone())
        .await
        .is_err());
    host.fail.store(true, Ordering::SeqCst);
    state.settings.mixed_port = 3080;
    assert!(repo.commit(state).await.is_err());
    assert_eq!(repo.state.settings.mixed_port, 2080);
    assert_eq!(std::fs::read(dir.path().join("state.enc")).unwrap(), before);
    drop(repo);
    host.fail.store(false, Ordering::SeqCst);
    assert_eq!(
        Repository::open(dir.path().into(), host)
            .await
            .unwrap()
            .state
            .profiles
            .len(),
        1
    );
}
#[tokio::test]
async fn engine_snapshots_hide_secrets_and_settings_rollback() {
    let dir = tempfile::tempdir().unwrap();
    let host = Arc::new(Fake::default());
    let engine = Engine::new(
        dir.path().into(),
        host.clone(),
        Arc::new(Mutex::new(Default::default())),
    )
    .await
    .unwrap();
    engine.dispatch("import",json!({"text":"trojan://private-password@one.example#One\ntrojan://other-password@two.example#Two"})).await.unwrap();
    let before = engine.snapshot().await;
    let serialized = before.to_string();
    for secret in ["private-password", "one.example", "outbound"] {
        assert!(!serialized.contains(secret));
    }
    assert_eq!(before["version"], lunaris_backend::VERSION);
    for patch in [
        json!({"mixed_port":1}),
        json!({"unknown":true}),
        json!({"verify_connection":1}),
    ] {
        assert!(engine.dispatch("settings", patch).await.is_err());
    }
    assert_eq!(engine.snapshot().await["settings"], before["settings"]);
    engine.shutdown().await.unwrap();
}

#[tokio::test]
async fn ping_sort_and_tray_preferences_migrate_and_survive_restart() {
    let old: Settings = serde_json::from_value(json!({"core":"mihomo"})).unwrap();
    assert!(old.auto_sort_ping && old.minimize_to_tray && old.close_to_tray);
    let dir = tempfile::tempdir().unwrap();
    let host = Arc::new(Fake::default());
    let engine = Engine::new(
        dir.path().into(),
        host.clone(),
        Arc::new(Mutex::new(Default::default())),
    )
    .await
    .unwrap();
    let patch = json!({"auto_sort_ping":false,"minimize_to_tray":false,"close_to_tray":false});
    engine.dispatch("settings", patch).await.unwrap();
    assert!(engine
        .dispatch("settings", json!({"auto_sort_ping":"false"}))
        .await
        .is_err());
    engine.shutdown().await.unwrap();
    drop(engine);
    let repo = Repository::open(dir.path().into(), host).await.unwrap();
    assert!(!repo.state.settings.auto_sort_ping);
    assert!(!repo.state.settings.minimize_to_tray);
    assert!(!repo.state.settings.close_to_tray);
}

#[tokio::test]
async fn tray_connect_is_idempotent_and_disconnect_stops_the_core() {
    let dir = tempfile::tempdir().unwrap();
    let host = Arc::new(Fake::default());
    let engine = Engine::new(
        dir.path().into(),
        host.clone(),
        Arc::new(Mutex::new(Default::default())),
    )
    .await
    .unwrap();
    assert!(engine.dispatch("connect", json!({})).await.is_err());
    engine
        .dispatch("import", json!({"text":uri()}))
        .await
        .unwrap();
    engine.dispatch("connect", json!({})).await.unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    engine.dispatch("connect", json!({})).await.unwrap();
    assert_eq!(host.starts.lock().unwrap().len(), 1);
    assert_eq!(engine.snapshot().await["status"], "connected");
    engine.dispatch("disconnect", json!({})).await.unwrap();
    assert_eq!(engine.snapshot().await["status"], "disconnected");
    engine.shutdown().await.unwrap();
}
#[tokio::test]
async fn engine_switch_waits_for_stop_acknowledgement() {
    let dir = tempfile::tempdir().unwrap();
    let host = Arc::new(Fake::default());
    let engine = Engine::new(
        dir.path().into(),
        host.clone(),
        Arc::new(Mutex::new(Default::default())),
    )
    .await
    .unwrap();
    engine
        .dispatch(
            "import",
            json!({"text":"trojan://first@one.example#One\ntrojan://second@two.example#Two"}),
        )
        .await
        .unwrap();
    engine.dispatch("toggle", json!({})).await.unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    let key = engine.snapshot().await["profiles"][1]["key"].clone();
    host.wait_stop.store(true, Ordering::SeqCst);
    let e = engine.clone();
    let switch = tokio::spawn(async move { e.dispatch("select", json!({"key":key})).await });
    tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    assert!(!switch.is_finished());
    assert_eq!(host.starts.lock().unwrap().len(), 1);
    host.wait_stop.store(false, Ordering::SeqCst);
    host.stop.notify_one();
    switch.await.unwrap().unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    assert_eq!(host.starts.lock().unwrap().len(), 2);
    engine.shutdown().await.unwrap();
}

#[tokio::test]
async fn subscription_metadata_survives_restart_and_failed_refresh_then_clears() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}/subscription", listener.local_addr().unwrap());
    let description = "Новости от создателя\nВторая строка";
    let body = "trojan://synthetic@example.com#Server";
    let encoded = subscriptions::b64(description.as_bytes());
    let responses = [
        format!("HTTP/1.1 200 OK\r\nAnnounce: base64:{encoded}\r\nSubscription-Userinfo: expire=1893456000\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()),
        "HTTP/1.1 503 Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_string(),
        format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()),
    ];
    let server = tokio::spawn(async move {
        for response in responses {
            let (mut stream, _) =
                tokio::time::timeout(std::time::Duration::from_secs(10), listener.accept())
                    .await
                    .unwrap()
                    .unwrap();
            let mut request = Vec::new();
            while !request.ends_with(b"\r\n\r\n") {
                let mut byte = [0];
                stream.read_exact(&mut byte).await.unwrap();
                request.extend(byte);
                assert!(request.len() <= 8192);
            }
            stream.write_all(response.as_bytes()).await.unwrap();
        }
    });
    let dir = tempfile::tempdir().unwrap();
    let host = Arc::new(Fake::default());
    let engine = Engine::new(
        dir.path().into(),
        host.clone(),
        Arc::new(Mutex::new(Default::default())),
    )
    .await
    .unwrap();
    engine
        .dispatch(
            "settings",
            json!({"update_on_start":false,"update_minutes":0}),
        )
        .await
        .unwrap();
    let snapshot = engine
        .dispatch("add_subscription", json!({"url":url}))
        .await
        .unwrap();
    let id = snapshot["subscriptions"][0]["id"].clone();
    assert_eq!(snapshot["subscriptions"][0]["description"], description);
    assert_eq!(
        snapshot["subscriptions"][0]["userinfo"]["expire"],
        1893456000u64
    );
    engine.shutdown().await.unwrap();
    drop(engine);
    let engine = Engine::new(
        dir.path().into(),
        host,
        Arc::new(Mutex::new(Default::default())),
    )
    .await
    .unwrap();
    assert_eq!(
        engine.snapshot().await["subscriptions"][0]["description"],
        description
    );
    assert!(engine
        .dispatch("update_subscription", json!({"id":id}))
        .await
        .is_err());
    let failed = engine.snapshot().await;
    assert_eq!(failed["subscriptions"][0]["description"], description);
    assert_eq!(
        failed["subscriptions"][0]["userinfo"]["expire"],
        1893456000u64
    );
    let refreshed = engine
        .dispatch("update_subscription", json!({"id":id}))
        .await
        .unwrap();
    assert!(refreshed["subscriptions"][0]["description"].is_null());
    assert_eq!(refreshed["subscriptions"][0]["userinfo"], json!({}));
    engine.shutdown().await.unwrap();
    server.await.unwrap();
}

// Keep the HTTP response pending until the test has exercised other commands.
async fn delayed_subscription() -> (
    String,
    Arc<tokio::sync::Notify>,
    Arc<tokio::sync::Notify>,
    tokio::task::JoinHandle<()>,
) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}/subscription", listener.local_addr().unwrap());
    let requested = Arc::new(tokio::sync::Notify::new());
    let release = Arc::new(tokio::sync::Notify::new());
    let (started, ready) = (requested.clone(), release.clone());
    let task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut request = Vec::new();
        while !request.ends_with(b"\r\n\r\n") {
            let mut byte = [0];
            stream.read_exact(&mut byte).await.unwrap();
            request.extend(byte);
            assert!(request.len() <= 8192);
        }
        started.notify_one();
        ready.notified().await;
        let body = "trojan://fresh@127.0.0.1:1#Fresh";
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        stream.write_all(response.as_bytes()).await.unwrap();
    });
    (url, requested, release, task)
}

async fn subscribed_engine(
    url: String,
    startup: bool,
) -> (tempfile::TempDir, Arc<Engine>, Arc<Fake>) {
    let dir = tempfile::tempdir().unwrap();
    let host = Arc::new(Fake::default());
    let mut repo = Repository::open(dir.path().into(), host.clone())
        .await
        .unwrap();
    let mut state = State::default();
    state.settings.update_on_start = startup;
    state.settings.update_minutes = 0;
    state.subscriptions.push(Subscription {
        id: "slow".into(),
        name: "Slow subscription".into(),
        url,
        userinfo: json!({}),
        ..Default::default()
    });
    state.profiles = vec![
        parser::parse_uri("trojan://old@127.0.0.1:1#Old", Some("slow")).unwrap(),
        parser::parse_uri("trojan://manual@127.0.0.1:1#Manual", None).unwrap(),
    ];
    state.selected = Some(state.profiles[0].key());
    repo.commit(state).await.unwrap();
    drop(repo);
    let engine = Engine::new(
        dir.path().into(),
        host.clone(),
        Arc::new(Mutex::new(Default::default())),
    )
    .await
    .unwrap();
    (dir, engine, host)
}

#[tokio::test]
async fn subscription_downloads_do_not_block_vpn_selection_measurement_or_settings() {
    use std::time::Duration;
    use tokio::time::timeout;
    for method in [
        "update_subscription",
        "update_all",
        "add_subscription",
        "startup",
    ] {
        let (url, requested, release, server) = delayed_subscription().await;
        let (_dir, engine, host) = subscribed_engine(url.clone(), method == "startup").await;
        let pending = if method == "startup" {
            None
        } else {
            let e = engine.clone();
            Some(tokio::spawn(async move {
                e.dispatch(method, json!({"id":"slow","url":url})).await
            }))
        };
        timeout(Duration::from_secs(3), requested.notified())
            .await
            .unwrap();
        let snapshot = timeout(
            Duration::from_secs(1),
            engine.dispatch("snapshot", json!({})),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(snapshot["profiles"].as_array().unwrap().len(), 2);
        // Selection and settings changed during download must survive the merge.
        let key = snapshot["profiles"][1]["key"].clone();
        for (command, args) in [
            ("select", json!({"key":key})),
            ("settings", json!({"ipv6":false})),
            ("toggle", json!({})),
        ] {
            timeout(Duration::from_secs(1), engine.dispatch(command, args))
                .await
                .expect("subscription download blocked a VPN command")
                .unwrap();
        }
        timeout(Duration::from_secs(1), async {
            while engine.snapshot().await["status"] != "connected" {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert_eq!(host.starts.lock().unwrap().len(), 1);
        for command in ["measure", "cancel_measure", "disconnect"] {
            timeout(
                Duration::from_secs(1),
                engine.dispatch(command, json!({"selected":true,"method":"tcp"})),
            )
            .await
            .expect("subscription download blocked ping/disconnect")
            .unwrap();
        }
        if let Some(pending) = &pending {
            assert!(!pending.is_finished());
        }
        release.notify_one();
        if let Some(pending) = pending {
            pending.await.unwrap().unwrap();
        }
        server.await.unwrap();
        timeout(Duration::from_secs(2), async {
            while !engine.snapshot().await["profiles"]
                .as_array()
                .unwrap()
                .iter()
                .any(|p| p["name"] == "Fresh")
            {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        let snapshot = engine.snapshot().await;
        assert_eq!(snapshot["selected"], key);
        assert_eq!(snapshot["settings"]["ipv6"], false);
        engine.shutdown().await.unwrap();
    }
}

#[tokio::test]
async fn removing_a_subscription_during_download_does_not_restore_its_profiles() {
    use std::time::Duration;
    use tokio::time::timeout;
    let (url, requested, release, server) = delayed_subscription().await;
    let (dir, engine, host) = subscribed_engine(url, false).await;
    let e = engine.clone();
    let pending = tokio::spawn(async move {
        e.dispatch("update_subscription", json!({"id":"slow"}))
            .await
    });
    timeout(Duration::from_secs(3), requested.notified())
        .await
        .unwrap();
    timeout(
        Duration::from_secs(1),
        engine.dispatch("remove_subscription", json!({"id":"slow"})),
    )
    .await
    .expect("subscription download blocked deletion")
    .unwrap();
    release.notify_one();
    assert!(pending.await.unwrap().is_err());
    server.await.unwrap();
    let snapshot = engine.snapshot().await;
    assert!(snapshot["subscriptions"].as_array().unwrap().is_empty());
    assert_eq!(snapshot["profiles"].as_array().unwrap().len(), 1);
    assert_eq!(snapshot["profiles"][0]["name"], "Manual");
    engine.shutdown().await.unwrap();
    drop(engine);
    let repo = Repository::open(dir.path().into(), host).await.unwrap();
    assert!(repo.state.subscriptions.is_empty());
    assert_eq!(repo.state.profiles.len(), 1);
}

#[tokio::test]
async fn shutdown_does_not_wait_for_subscription_download_or_accept_its_result() {
    use std::time::Duration;
    use tokio::time::timeout;
    let (url, requested, release, server) = delayed_subscription().await;
    let (_dir, engine, _host) = subscribed_engine(url, false).await;
    let before = engine.snapshot().await;
    let e = engine.clone();
    let pending = tokio::spawn(async move { e.dispatch("update_all", json!({})).await });
    timeout(Duration::from_secs(3), requested.notified())
        .await
        .unwrap();
    timeout(Duration::from_secs(1), engine.shutdown())
        .await
        .expect("subscription download blocked shutdown")
        .unwrap();
    release.notify_one();
    pending.await.unwrap().unwrap();
    server.await.unwrap();
    assert_eq!(engine.snapshot().await["profiles"], before["profiles"]);
    assert_eq!(
        engine.snapshot().await["subscriptions"],
        before["subscriptions"]
    );
}

#[test]
fn old_subscriptions_without_description_remain_readable() {
    let subscription: Subscription = serde_json::from_value(
        json!({"id":"old","name":"Existing","url":"https://example.com/sub"}),
    )
    .unwrap();
    assert!(subscription.description.is_none());
    assert_eq!(subscription.name, "Existing");
}

#[cfg(windows)]
#[test]
fn dpapi_roundtrip_and_wrong_data_fails() {
    let plain = b"synthetic credentials";
    let cipher = lunaris_backend::windows::dpapi(plain, false).unwrap();
    assert_ne!(cipher, plain);
    assert_eq!(
        lunaris_backend::windows::dpapi(&cipher, true).unwrap(),
        plain
    );
    assert!(lunaris_backend::windows::dpapi(b"invalid", true).is_err());
}
