use super::{initialize, Backend};
use serde_json::{json, Value};
use std::sync::atomic::{AtomicBool, Ordering};
use tauri::{
    menu::{Menu, MenuItem, PredefinedMenuItem},
    tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent},
    Emitter, Manager, WindowEvent,
};

struct Desktop {
    minimize: AtomicBool,
    close: AtomicBool,
    quitting: AtomicBool,
    status: MenuItem<tauri::Wry>,
    connect: MenuItem<tauri::Wry>,
    disconnect: MenuItem<tauri::Wry>,
    measure: MenuItem<tauri::Wry>,
    update: MenuItem<tauri::Wry>,
}

fn show(app: &tauri::AppHandle) {
    if let Some(window) = app.get_webview_window("main") {
        let _ = window.show();
        let _ = window.unminimize();
        let _ = window.set_focus();
    }
}

pub fn preferences(app: &tauri::AppHandle, snapshot: &Value) {
    if !snapshot["settings"].is_object() {
        return;
    }
    let desktop = app.state::<Desktop>();
    desktop.minimize.store(
        snapshot["settings"]["minimize_to_tray"]
            .as_bool()
            .unwrap_or(true),
        Ordering::Relaxed,
    );
    desktop.close.store(
        snapshot["settings"]["close_to_tray"]
            .as_bool()
            .unwrap_or(true),
        Ordering::Relaxed,
    );
}

fn refresh(app: &tauri::AppHandle, snapshot: &Value) {
    preferences(app, snapshot);
    let desktop = app.state::<Desktop>();
    let status = snapshot["status"].as_str().unwrap_or("disconnected");
    let running = matches!(status, "connecting" | "connected" | "disconnecting");
    let text = match status {
        "connected" => "Подключено",
        "connecting" => "Подключается…",
        "disconnecting" => "Отключается…",
        "error" => "Ошибка подключения",
        _ => "Отключено",
    };
    let _ = desktop.status.set_text(text);
    let _ = desktop
        .connect
        .set_enabled(!running && snapshot["selected"].is_string());
    let _ = desktop
        .disconnect
        .set_enabled(running && status != "disconnecting");
    let measuring = snapshot["measuring"].as_bool().unwrap_or(false);
    let _ = desktop.measure.set_text(if measuring {
        "Остановить проверку пинга"
    } else {
        "Проверить пинг серверов"
    });
    let _ = desktop.measure.set_enabled(
        snapshot["profiles"]
            .as_array()
            .is_some_and(|p| !p.is_empty())
            && !matches!(status, "connecting" | "disconnecting"),
    );
    let _ = desktop.update.set_enabled(
        snapshot["subscriptions"]
            .as_array()
            .is_some_and(|s| !s.is_empty()),
    );
    if let Some(tray) = app.tray_by_id("lunaris") {
        let _ = tray.set_tooltip(Some(format!("Lunaris client · {text}")));
    }
}

fn menu_event(app: &tauri::AppHandle, event: tauri::menu::MenuEvent) {
    let id = event.id.as_ref();
    match id {
        "open" => show(app),
        "settings" => {
            show(app);
            let _ = app.emit("desktop-navigate", "settings");
        }
        "quit" => {
            app.state::<Desktop>()
                .quitting
                .store(true, Ordering::Relaxed);
            // RunEvent::Exit shuts down the engine and restores the system proxy.
            app.exit(0);
        }
        "connect" | "disconnect" | "measure" | "update" => {
            let app = app.clone();
            let id = id.to_string();
            tauri::async_runtime::spawn(async move {
                let result: lunaris_backend::Result<Value> = async {
                    let backend = app.state::<Backend>();
                    let engine = backend.0.get_or_try_init(|| initialize(&app)).await?;
                    let snapshot = engine.snapshot().await;
                    let (method, args) = match id.as_str() {
                        "measure" if snapshot["measuring"] == true => ("cancel_measure", json!({})),
                        "measure" => ("measure", json!({"method":"tcp"})),
                        "update" => ("update_all", json!({})),
                        _ => (id.as_str(), json!({})),
                    };
                    engine.dispatch(method, args).await
                }
                .await;
                match result {
                    Ok(snapshot) => refresh(&app, &snapshot),
                    Err(error) => {
                        show(&app);
                        let _ = app.emit("desktop-error", error);
                    }
                }
            });
        }
        _ => {}
    }
}

pub fn setup(app: &mut tauri::App) -> std::result::Result<(), Box<dyn std::error::Error>> {
    let status = MenuItem::with_id(app, "status", "Открываем хранилище…", false, None::<&str>)?;
    let open = MenuItem::with_id(app, "open", "Открыть Lunaris client", true, None::<&str>)?;
    let connect = MenuItem::with_id(app, "connect", "Подключить", false, None::<&str>)?;
    let disconnect = MenuItem::with_id(app, "disconnect", "Отключить", false, None::<&str>)?;
    let measure = MenuItem::with_id(
        app,
        "measure",
        "Проверить пинг серверов",
        false,
        None::<&str>,
    )?;
    let update = MenuItem::with_id(app, "update", "Обновить подписки", false, None::<&str>)?;
    let settings = MenuItem::with_id(app, "settings", "Настройки", true, None::<&str>)?;
    let quit = MenuItem::with_id(app, "quit", "Выход", true, None::<&str>)?;
    let separator = PredefinedMenuItem::separator(app)?;
    let separator2 = PredefinedMenuItem::separator(app)?;
    let menu = Menu::with_items(
        app,
        &[
            &status,
            &open,
            &separator,
            &connect,
            &disconnect,
            &measure,
            &update,
            &settings,
            &separator2,
            &quit,
        ],
    )?;
    let icon = app
        .default_window_icon()
        .ok_or("Application icon is missing")?
        .clone();
    TrayIconBuilder::with_id("lunaris")
        .icon(icon)
        .tooltip("Lunaris client")
        .menu(&menu)
        .show_menu_on_left_click(false)
        .on_menu_event(menu_event)
        .on_tray_icon_event(|tray, event| {
            if matches!(
                event,
                TrayIconEvent::Click {
                    button: MouseButton::Left,
                    button_state: MouseButtonState::Up,
                    ..
                }
            ) {
                show(tray.app_handle());
            }
        })
        .build(app)?;
    app.manage(Desktop {
        minimize: AtomicBool::new(true),
        close: AtomicBool::new(true),
        quitting: AtomicBool::new(false),
        status,
        connect,
        disconnect,
        measure,
        update,
    });
    let handle = app.handle().clone();
    tauri::async_runtime::spawn(async move {
        loop {
            if let Some(engine) = handle.state::<Backend>().0.get() {
                refresh(&handle, &engine.snapshot().await);
            }
            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        }
    });
    Ok(())
}

pub fn window_event(window: &tauri::Window, event: &WindowEvent) {
    let Some(desktop) = window.try_state::<Desktop>() else {
        return;
    };
    if window.label() != "main" || desktop.quitting.load(Ordering::Relaxed) {
        return;
    }
    match event {
        WindowEvent::CloseRequested { api, .. } if desktop.close.load(Ordering::Relaxed) => {
            // Prevent destruction only after hiding succeeds; the tray can reopen it.
            if window.hide().is_ok() {
                api.prevent_close();
            }
        }
        WindowEvent::Resized(_) if desktop.minimize.load(Ordering::Relaxed) => {
            if window.is_minimized().unwrap_or(false) {
                let _ = window.hide();
            }
        }
        _ => {}
    }
}
