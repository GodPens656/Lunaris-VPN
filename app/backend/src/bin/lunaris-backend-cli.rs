//! Test/diagnostic entry point. The GUI links the same backend directly.
use lunaris_backend::{
    config,
    engine::{Engine, Host},
    models::{Profile, Settings},
    parser, Result,
};
use serde_json::{json, Value};
use std::{
    io::{BufRead, Write},
    sync::Arc,
};
fn evaluate(v: Value) -> Result<Value> {
    match v["method"].as_str().unwrap_or("") {
        "parse" => {
            let p = parser::parse_uri(v["uri"].as_str().unwrap_or(""), v["source"].as_str())?;
            Ok(
                json!({"identity":p.identity(),"key":p.key(),"requires_xray":p.requires_xray(),"profile":p}),
            )
        }
        "import" => {
            Ok(serde_json::to_value(parser::import(v["text"].as_str().unwrap_or(""))?).unwrap())
        }
        "config" => {
            let p: Profile = serde_json::from_value(v["profile"].clone())
                .map_err(|_| "Некорректный профиль.")?;
            let s: Settings =
                serde_json::from_value(v.get("settings").cloned().unwrap_or(json!({})))
                    .map_err(|_| "Некорректные настройки.")?;
            let hosts = v.get("hosts");
            let kind = v["core"].as_str().unwrap_or("sing-box");
            let secret = v["secret"].as_str().unwrap_or("api-secret");
            let password = v["password"].as_str().unwrap_or("local-secret");
            let port = v["port"].as_u64().unwrap_or(1080) as u16;
            match kind {
                "xray" => config::xray(&p, port, password, &s, hosts),
                "xray-desktop" => config::xray_desktop(&p, &s, hosts, None),
                "mihomo" => config::mihomo(&p, &s, secret, hosts),
                "mihomo-proxy" => config::mihomo_proxy(&p),
                "android" => config::android(&p, &s, secret, password),
                _ => config::sing_box(
                    &p,
                    &s,
                    secret,
                    v["android"].as_bool().unwrap_or(false),
                    v.get("sidecar").filter(|v| !v.is_null()).cloned(),
                    hosts,
                ),
            }
        }
        "initial" => {
            let packet = lunaris_backend::latency::initial(
                &[0, 1, 2, 3, 4, 5, 6, 7],
                &[8, 9, 10, 11, 12, 13, 14, 15],
            )
            .ok_or("QUIC Initial недоступен.")?;
            Ok(json!(lunaris_backend::subscriptions::b64(&packet)))
        }
        "quic_reply" => Ok(json!(lunaris_backend::latency::is_reply(
            &parser::unbase64(v["data"].as_str().unwrap_or(""))?,
            &[0, 1, 2, 3, 4, 5, 6, 7],
            &[8, 9, 10, 11, 12, 13, 14, 15]
        ))),
        _ => Err("Неизвестная команда.".into()),
    }
}
#[tokio::main]
async fn main() {
    #[cfg(windows)]
    if lunaris_backend::windows::guardian_from_args()
        || lunaris_backend::windows::import_from_args()
    {
        return;
    }
    let engine: Option<Arc<Engine>> = if std::env::args().any(|s| s == "--engine") {
        #[cfg(windows)]
        {
            let directory = std::path::PathBuf::from(
                std::env::var_os("LUNARIS_DATA_DIR")
                    .expect("Set isolated LUNARIS_DATA_DIR for diagnostics"),
            );
            let assets = std::env::var_os("LUNARIS_ASSETS_DIR")
                .map(std::path::PathBuf::from)
                .unwrap_or_else(|| {
                    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../assets")
                });
            let log = Arc::new(std::sync::Mutex::new(Default::default()));
            let host = Arc::new(if std::env::args().any(|s| s == "--probe") {
                lunaris_backend::windows::WindowsHost::isolated_probe(
                    directory.join("runtime"),
                    assets,
                    log.clone(),
                )
            } else {
                lunaris_backend::windows::WindowsHost::new(directory.clone(), assets, log.clone())
                    .await
                    .expect("Windows host")
            }) as Arc<dyn Host>;
            Some(
                Engine::new(directory, host, log)
                    .await
                    .expect("Protected storage"),
            )
        }
        #[cfg(not(windows))]
        {
            None
        }
    } else {
        None
    };
    for line in std::io::stdin().lock().lines() {
        let Ok(line) = line else {
            break;
        };
        if line.len() > parser::MAX_BODY + 65536 {
            break;
        }
        let result = match parser::strict_json(&line) {
            Ok(v) => {
                if v["method"] == "diagnostics" {
                    Ok(
                        json!({"probe":std::env::args().any(|s|s=="--probe"),"version":lunaris_backend::VERSION}),
                    )
                } else if let Some(engine) = engine.as_ref() {
                    engine
                        .dispatch(
                            v["method"].as_str().unwrap_or(""),
                            v.get("args").cloned().unwrap_or(json!({})),
                        )
                        .await
                } else {
                    evaluate(v)
                }
            }
            Err(e) => Err(e),
        };
        let value = match result {
            Ok(v) => json!({"ok":v}),
            Err(e) => json!({"error":e}),
        };
        println!("{value}");
        let _ = std::io::stdout().flush();
    }
    if let Some(e) = engine {
        let _ = e.shutdown().await;
    }
}
