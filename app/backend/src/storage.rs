use crate::{engine::Host, models::State, Result};
use fs2::FileExt;
use std::{
    fs::{self, File, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
    sync::Arc,
};
pub const MAGIC: &[u8] = b"SEVER2\0";
pub struct Repository {
    pub directory: PathBuf,
    pub state: State,
    host: Arc<dyn Host>,
    _lock: File,
}
impl Repository {
    pub async fn open(directory: PathBuf, host: Arc<dyn Host>) -> Result<Self> {
        fs::create_dir_all(&directory)
            .map_err(|_| "Не удалось открыть приватный каталог приложения.")?;
        let lock = OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(directory.join("state.lock"))
            .map_err(|_| "Не удалось открыть блокировку хранилища.")?;
        lock.try_lock_exclusive()
            .map_err(|_| "Lunaris client уже запущен. Закройте другой экземпляр приложения.")?;
        let path = directory.join("state.enc");
        let state = if path.exists() {
            let data =
                fs::read(path).map_err(|_| "Хранилище недоступно. Исходный файл сохранён.")?;
            let encrypted = data
                .strip_prefix(MAGIC)
                .ok_or("Хранилище повреждено. Исходный файл сохранён.")?;
            let plain = host
                .decrypt(encrypted)
                .await
                .map_err(|_| "Хранилище повреждено или недоступно. Исходный файл сохранён.")?;
            let mut value: serde_json::Value = serde_json::from_slice(&plain)
                .map_err(|_| "Хранилище повреждено. Исходный файл сохранён.")?;
            if !host.android() {
                if let Some(settings) = value
                    .get_mut("settings")
                    .and_then(serde_json::Value::as_object_mut)
                {
                    settings
                        .entry("core")
                        .or_insert(serde_json::json!("mihomo"));
                }
            }
            let state: State = serde_json::from_value(value)
                .map_err(|_| "Хранилище повреждено. Исходный файл сохранён.")?;
            state.settings.validate()?;
            state
        } else {
            State::default()
        };
        Ok(Self {
            directory,
            state,
            host,
            _lock: lock,
        })
    }
    pub async fn commit(&mut self, state: State) -> Result<()> {
        state.settings.validate()?;
        let plain =
            serde_json::to_vec(&state).map_err(|_| "Не удалось сериализовать настройки.")?;
        let encrypted = self.host.encrypt(&plain).await?;
        let mut data = MAGIC.to_vec();
        data.extend(encrypted);
        atomic_write(&self.directory.join("state.enc"), &data)?;
        self.state = state;
        Ok(())
    }
}
pub fn atomic_write(path: &Path, data: &[u8]) -> Result<()> {
    let tmp = path.with_file_name(format!(
        "{}.tmp-{}",
        path.file_name().unwrap_or_default().to_string_lossy(),
        uuid::Uuid::new_v4()
    ));
    let result = (|| -> std::io::Result<()> {
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(&tmp)?;
        file.write_all(data)?;
        file.sync_all()?;
        drop(file);
        #[cfg(windows)]
        {
            use std::os::windows::ffi::OsStrExt;
            use windows_sys::Win32::Storage::FileSystem::{
                MoveFileExW, MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH,
            };
            let a: Vec<u16> = tmp.as_os_str().encode_wide().chain(Some(0)).collect();
            let b: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
            if unsafe {
                MoveFileExW(
                    a.as_ptr(),
                    b.as_ptr(),
                    MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
                )
            } == 0
            {
                return Err(std::io::Error::last_os_error());
            }
        }
        #[cfg(not(windows))]
        fs::rename(&tmp, path)?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(tmp);
        return Err("Не удалось сохранить данные. Изменения не применены.".into());
    }
    Ok(())
}
