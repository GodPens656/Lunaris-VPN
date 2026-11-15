use tauri::{plugin::{Builder, TauriPlugin}, Runtime};
#[cfg(target_os = "android")]
use tauri::{Manager, plugin::PluginHandle};

#[cfg(target_os = "android")]
pub struct LunarisNative<R: Runtime>(PluginHandle<R>);

#[cfg(target_os = "android")]
impl<R: Runtime> LunarisNative<R> {
    pub fn call(&self, command: &str, args: serde_json::Value) -> Result<serde_json::Value, String> {
        self.0.run_mobile_plugin(command, args).map_err(|e| e.to_string())
    }
}

pub fn init<R: Runtime>() -> TauriPlugin<R> {
    Builder::new("lunaris-native")
        .setup(|_app, _api| {
            #[cfg(target_os = "android")]
            {
                let handle = _api.register_android_plugin("dev.sever.vpn", "LunarisPlugin")?;
                _app.manage(LunarisNative(handle));
            }
            Ok(())
        }).build()
}
