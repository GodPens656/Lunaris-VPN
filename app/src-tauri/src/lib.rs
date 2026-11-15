use lunaris_backend::{
    engine::{Engine, Host, Log},
    Result,
};
use serde_json::Value;
use std::sync::Arc;
use tauri::Manager;

#[cfg(windows)]
mod desktop;

#[derive(Default)]
struct Backend(tokio::sync::OnceCell<Arc<Engine>>);

async fn initialize(app: &tauri::AppHandle) -> Result<Arc<Engine>> {
    let log: Log = Arc::new(std::sync::Mutex::new(Default::default()));
    #[cfg(target_os = "android")]
    let (directory, host) = {
        let handle = app.clone();
        let call = Arc::new(move |method: &str, args: Value| -> Result<Value> {
            let native = handle.state::<tauri_plugin_lunaris_native::LunarisNative<tauri::Wry>>();
            let response =
                native.call("native", serde_json::json!({"method":method,"args":args}))?;
            if let Some(error) = response["error"].as_str() {
                Err(error.into())
            } else {
                Ok(response["ok"].clone())
            }
        });
        let host = Arc::new(lunaris_backend::engine::AndroidHost { call });
        let info = host
            .invoke("storage_directory", serde_json::json!({}))
            .await?;
        let directory =
            std::path::PathBuf::from(info.as_str().ok_or("Нет приватного каталога Android.")?);
        (directory, host as Arc<dyn Host>)
    };
    #[cfg(windows)]
    let (directory, host) = {
        let directory = std::env::var_os("LUNARIS_DATA_DIR")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|| {
                std::path::PathBuf::from(std::env::var_os("LOCALAPPDATA").unwrap_or_default())
                    .join("SeverVPN")
            });
        let runtime = app
            .path()
            .resource_dir()
            .map_err(|_| "Не найден каталог ресурсов.")?
            .join("runtime/assets");
        let assets = std::env::var_os("LUNARIS_ASSETS_DIR")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|| {
                if runtime.is_dir() {
                    runtime
                } else {
                    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../assets")
                }
            });
        let host = Arc::new(
            lunaris_backend::windows::WindowsHost::new(directory.clone(), assets, log.clone())
                .await?,
        ) as Arc<dyn Host>;
        (directory, host)
    };
    #[cfg(any(windows, target_os = "android"))]
    {
        Engine::new(directory, host, log).await
    }
    #[cfg(not(any(windows, target_os = "android")))]
    {
        let _ = (app, log);
        Err("Поддерживаются Windows и Android.".into())
    }
}

#[tauri::command]
async fn api(app: tauri::AppHandle, method: String, args: Option<Value>) -> Result<Value> {
    let backend = app.state::<Backend>();
    let engine = backend.0.get_or_try_init(|| initialize(&app)).await?;
    let result = engine
        .dispatch(&method, args.unwrap_or_else(|| serde_json::json!({})))
        .await;
    #[cfg(windows)]
    if let Ok(snapshot) = &result {
        desktop::preferences(&app, snapshot);
    }
    result
}

#[tauri::command]
async fn hide_to_tray(app: tauri::AppHandle) -> Result<()> {
    #[cfg(windows)]
    {
        app.get_webview_window("main")
            .ok_or("Окно приложения недоступно.")?
            .hide()
            .map_err(|_| "Не удалось свернуть окно в трей.".to_string())
    }
    #[cfg(not(windows))]
    {
        let _ = app;
        Err("Трей доступен только в Windows.".into())
    }
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    #[cfg(windows)]
    if lunaris_backend::windows::guardian_from_args()
        || lunaris_backend::windows::import_from_args()
    {
        return;
    }
    let builder = tauri::Builder::default()
        .plugin(tauri_plugin_lunaris_native::init())
        .manage(Backend::default())
        .invoke_handler(tauri::generate_handler![api, hide_to_tray]);
    #[cfg(windows)]
    let builder = builder
        .setup(desktop::setup)
        .on_window_event(desktop::window_event);
    let app = builder
        .build(tauri::generate_context!())
        .expect("Lunaris client could not start");
    app.run(|app, event| {
        if let tauri::RunEvent::Exit = event {
            if let Some(engine) = app.state::<Backend>().0.get() {
                let _ = tauri::async_runtime::block_on(engine.shutdown());
            }
        }
    });
}
