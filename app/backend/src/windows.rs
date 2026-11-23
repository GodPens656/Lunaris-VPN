//! Windows platform operations: DPAPI, process lifetime, WinINET and URL inbox.
use crate::{
    config,
    engine::{secret, Host, Log},
    flclash,
    latency::{self, Latency},
    models::*,
    storage::atomic_write,
    Result,
};
use async_trait::async_trait;
use serde_json::{json, Value};
use std::{
    fs,
    path::{Path, PathBuf},
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::{
    io::{AsyncBufReadExt, BufReader},
    net::windows::named_pipe::ServerOptions,
    process::{Child, Command},
    sync::Mutex,
    task::JoinHandle,
};
use windows_sys::Win32::{
    Foundation::*,
    Security::Cryptography::*,
    System::{JobObjects::*, Threading::*},
};
use winreg::{enums::*, RegKey};
fn wide(s: impl AsRef<std::ffi::OsStr>) -> Vec<u16> {
    use std::os::windows::ffi::OsStrExt;
    s.as_ref().encode_wide().chain(Some(0)).collect()
}
pub fn dpapi(data: &[u8], decrypt: bool) -> Result<Vec<u8>> {
    unsafe {
        let input = CRYPT_INTEGER_BLOB {
            cbData: data.len() as u32,
            pbData: data.as_ptr() as *mut u8,
        };
        let mut output: CRYPT_INTEGER_BLOB = std::mem::zeroed();
        let ok = if decrypt {
            CryptUnprotectData(
                &input,
                std::ptr::null_mut(),
                std::ptr::null(),
                std::ptr::null(),
                std::ptr::null(),
                1,
                &mut output,
            )
        } else {
            CryptProtectData(
                &input,
                wide("Lunaris client").as_ptr(),
                std::ptr::null(),
                std::ptr::null(),
                std::ptr::null(),
                1,
                &mut output,
            )
        };
        if ok == 0 {
            return Err("Не удалось получить доступ к защищённому хранилищу Windows.".into());
        }
        let result = std::slice::from_raw_parts(output.pbData, output.cbData as usize).to_vec();
        LocalFree(output.pbData as _);
        Ok(result)
    }
}
struct NativeHandle(usize);
impl Drop for NativeHandle {
    fn drop(&mut self) {
        if self.0 != 0 {
            unsafe {
                CloseHandle(self.0 as HANDLE);
            }
        }
    }
}
fn single_instance(directory: &Path) -> Result<NativeHandle> {
    use sha2::{Digest, Sha256};
    let name = if std::env::var_os("LUNARIS_DATA_DIR").is_some() {
        format!(
            "Local\\SeverVPN-{}",
            &format!(
                "{:x}",
                Sha256::digest(directory.to_string_lossy().as_bytes())
            )[..16]
        )
    } else {
        "Local\\SeverVPN".into()
    };
    let h = unsafe { CreateMutexW(std::ptr::null(), 0, wide(name).as_ptr()) };
    if h.is_null() {
        return Err("Не удалось создать блокировку приложения.".into());
    }
    let handle = NativeHandle(h as usize);
    if unsafe { GetLastError() } == 183 {
        return Err("Lunaris client уже запущен. Закройте другой экземпляр приложения.".into());
    }
    Ok(handle)
}
struct Job(NativeHandle);
impl Job {
    fn new() -> Result<Self> {
        unsafe {
            let h = CreateJobObjectW(std::ptr::null(), std::ptr::null());
            if h.is_null() {
                return Err("Не удалось создать Job Object.".into());
            }
            let job = Self(NativeHandle(h as usize));
            let mut limits: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = std::mem::zeroed();
            limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
            if SetInformationJobObject(
                h,
                JobObjectExtendedLimitInformation,
                &limits as *const _ as _,
                std::mem::size_of_val(&limits) as u32,
            ) == 0
            {
                return Err("Windows не разрешил защиту процесса ядра Job Object.".into());
            }
            Ok(job)
        }
    }
    fn assign(&self, pid: u32) -> Result<()> {
        unsafe {
            let p = OpenProcess(PROCESS_SET_QUOTA | PROCESS_TERMINATE, 0, pid);
            if p.is_null() {
                return Err("Не удалось взять процесс ядра под контроль.".into());
            }
            let guard = NativeHandle(p as usize);
            if AssignProcessToJobObject(self.0 .0 as HANDLE, guard.0 as HANDLE) == 0 {
                return Err("Не удалось привязать процесс ядра к приложению.".into());
            }
            Ok(())
        }
    }
}
const PROXY_NAMES: [&str; 4] = [
    "ProxyEnable",
    "ProxyServer",
    "ProxyOverride",
    "AutoConfigURL",
];
fn internet_key() -> Result<RegKey> {
    RegKey::predef(HKEY_CURRENT_USER)
        .open_subkey_with_flags(
            r"Software\Microsoft\Windows\CurrentVersion\Internet Settings",
            KEY_READ | KEY_WRITE,
        )
        .map_err(|_| "Не удалось открыть настройки системного прокси.".into())
}
fn reg_read(key: &RegKey, name: &str) -> Result<Value> {
    match key.get_raw_value(name) {
        Ok(v) => {
            use winreg::types::FromRegValue;
            let data = match v.vtype {
                REG_DWORD => {
                    json!(u32::from_reg_value(&v).map_err(|_| "Некорректный параметр прокси.")?)
                }
                REG_SZ | REG_EXPAND_SZ => {
                    json!(String::from_reg_value(&v).map_err(|_| "Некорректный параметр прокси.")?)
                }
                _ => return Err("Неизвестный тип параметра прокси. Настройки сохранены.".into()),
            };
            Ok(json!([data, v.vtype as u32]))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Value::Null),
        Err(_) => Err("Не удалось прочитать системный прокси.".into()),
    }
}
fn reg_write(key: &RegKey, name: &str, value: &Value) -> Result<()> {
    let result = if value.is_null() {
        match key.delete_value(name) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            v => v,
        }
    } else {
        let kind = value[1].as_u64().ok_or("Некорректный журнал прокси.")?;
        let (bytes, vtype) = if kind == 4 {
            (
                (value[0].as_u64().ok_or("Некорректный журнал прокси.")? as u32)
                    .to_le_bytes()
                    .to_vec(),
                REG_DWORD,
            )
        } else if kind == 1 || kind == 2 {
            let bytes = wide(value[0].as_str().ok_or("Некорректный журнал прокси.")?)
                .iter()
                .flat_map(|v| v.to_le_bytes())
                .collect();
            (bytes, if kind == 1 { REG_SZ } else { REG_EXPAND_SZ })
        } else {
            return Err("Некорректный журнал прокси.".into());
        };
        key.set_raw_value(name, &winreg::RegValue { bytes, vtype })
    };
    result.map_err(|_| "Не удалось изменить системный прокси.".into())
}
fn notify() {
    unsafe {
        windows_sys::Win32::Networking::WinInet::InternetSetOptionW(
            std::ptr::null(),
            39,
            std::ptr::null(),
            0,
        );
        windows_sys::Win32::Networking::WinInet::InternetSetOptionW(
            std::ptr::null(),
            37,
            std::ptr::null(),
            0,
        );
    }
}
pub fn restore_proxy(journal: &Path) -> Result<()> {
    if !journal.exists() {
        return Ok(());
    }
    let error = "Не удалось восстановить системный прокси. Журнал восстановления сохранён.";
    let encrypted = fs::read(journal).map_err(|_| error)?;
    let record: Value = serde_json::from_slice(&dpapi(&encrypted, true)?).map_err(|_| error)?;
    let key = internet_key()?;
    for name in PROXY_NAMES {
        let applied = record["applied"].get(name).ok_or(error)?;
        let previous = record["previous"].get(name).ok_or(error)?;
        if reg_read(&key, name)? == *applied {
            reg_write(&key, name, previous)?;
        }
    }
    notify();
    fs::remove_file(journal).map_err(|_| error)?;
    Ok(())
}
struct Proxy {
    journal: PathBuf,
    guardian: Option<std::process::Child>,
}
impl Proxy {
    fn new(directory: &Path) -> Self {
        Self {
            journal: directory.join("proxy.dpapi"),
            guardian: None,
        }
    }
    fn apply(&mut self, port: u16) -> Result<()> {
        restore_proxy(&self.journal)?;
        let key = internet_key()?;
        let mut previous = json!({});
        for name in PROXY_NAMES {
            previous[name] = reg_read(&key, name)?;
        }
        let applied = json!({"ProxyEnable":[1,4],"ProxyServer":[format!("http=127.0.0.1:{port};https=127.0.0.1:{port};socks=127.0.0.1:{port}"),1],"ProxyOverride":["<local>;localhost;127.*;[::1]",1],"AutoConfigURL":null});
        atomic_write(
            &self.journal,
            &dpapi(
                json!({"previous":previous,"applied":applied})
                    .to_string()
                    .as_bytes(),
                false,
            )?,
        )?;
        let ready = self.journal.with_extension("ready");
        let _ = fs::remove_file(&ready);
        use std::os::windows::process::CommandExt;
        self.guardian = Some(
            std::process::Command::new(
                std::env::current_exe().map_err(|_| "Не найден исполняемый файл приложения.")?,
            )
            .arg("--proxy-guardian")
            .arg(std::process::id().to_string())
            .arg(&self.journal)
            .arg(&ready)
            .creation_flags(0x08000000)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .map_err(|_| "Не удалось запустить восстановление системного прокси.")?,
        );
        let deadline = Instant::now() + Duration::from_secs(8);
        while !ready.exists() {
            if Instant::now() > deadline
                || self
                    .guardian
                    .as_mut()
                    .unwrap()
                    .try_wait()
                    .map_or(true, |v| v.is_some())
            {
                self.restore()?;
                return Err(
                    "Не удалось запустить восстановление системного прокси. Прокси не включён."
                        .into(),
                );
            }
            std::thread::sleep(Duration::from_millis(25));
        }
        let _ = fs::remove_file(ready);
        for name in PROXY_NAMES {
            if let Err(error) = reg_write(&key, name, &applied[name]) {
                let _ = self.restore();
                return Err(error);
            }
        }
        notify();
        Ok(())
    }
    fn restore(&mut self) -> Result<()> {
        restore_proxy(&self.journal)?;
        if let Some(mut child) = self.guardian.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
        Ok(())
    }
}
impl Drop for Proxy {
    fn drop(&mut self) {
        let _ = self.restore();
    }
}
/// Called before Tauri starts. A Rust helper restores the journal after a crash.
pub fn guardian_from_args() -> bool {
    let args = std::env::args_os().collect::<Vec<_>>();
    if args.get(1).is_none_or(|v| v != "--proxy-guardian") {
        return false;
    }
    if args.len() == 5 {
        if let Ok(pid) = args[2].to_string_lossy().parse::<u32>() {
            unsafe {
                let parent = OpenProcess(0x00100000, 0, pid);
                if !parent.is_null() {
                    let guard = NativeHandle(parent as usize);
                    let _ = fs::write(&args[4], b"ready");
                    WaitForSingleObject(guard.0 as HANDLE, INFINITE);
                }
                let _ = restore_proxy(Path::new(&args[3]));
            }
        }
    }
    true
}
fn command(exe: impl AsRef<std::ffi::OsStr>) -> Command {
    let mut c = Command::new(exe);
    c.creation_flags(0x08000000).kill_on_drop(true);
    c
}
async fn checked(exe: impl AsRef<std::ffi::OsStr>, args: &[&str], log: &Log) -> Result<String> {
    let mut c = command(exe);
    c.args(args);
    let output = tokio::time::timeout(Duration::from_secs(15), c.output())
        .await
        .map_err(|_| "Ядро не ответило за 15 секунд.")?
        .map_err(|_| "Не удалось запустить ядро.")?;
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    if !output.status.success() {
        log.lock().unwrap_or_else(|e| e.into_inner()).add(&text);
        return Err(
            "Ядро отклонило конфигурацию. Подробности доступны в очищенном журнале.".into(),
        );
    }
    Ok(text)
}
async fn restrict(directory: &Path) -> Result<()> {
    fs::create_dir_all(directory).map_err(|_| "Не удалось создать каталог конфигурации.")?;
    let o = command("whoami.exe")
        .args(["/user", "/fo", "csv", "/nh"])
        .output()
        .await
        .map_err(|_| "Не удалось определить пользователя Windows.")?;
    let text = String::from_utf8_lossy(&o.stdout);
    let re = regex::Regex::new(r"S-1-5-21-(?:\d+-){2}\d+-\d+").unwrap();
    let sid = re
        .find(&text)
        .ok_or("Не удалось определить SID пользователя.")?
        .as_str();
    let status = command("icacls.exe")
        .arg(directory)
        .args([
            "/inheritance:r",
            "/grant:r",
            &format!("*{sid}:(OI)(CI)F"),
            "*S-1-5-18:(OI)(CI)F",
        ])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .await
        .map_err(|_| "Не удалось защитить каталог конфигурации.")?;
    if !status.success() {
        return Err("Не удалось защитить каталог конфигурации.".into());
    }
    Ok(())
}
pub fn free_port(excluded: &[u16]) -> Result<u16> {
    for _ in 0..128 {
        let tcp = std::net::TcpListener::bind("127.0.0.1:0")
            .map_err(|_| "Не удалось выбрать локальный порт.")?;
        let p = tcp
            .local_addr()
            .map_err(|_| "Не удалось выбрать локальный порт.")?
            .port();
        if !excluded.contains(&p) && std::net::UdpSocket::bind(("127.0.0.1", p)).is_ok() {
            return Ok(p);
        }
    }
    Err("Не удалось выбрать свободный TCP/UDP-порт.".into())
}
enum CoreApi {
    FlClash(flclash::Core),
    Xray {
        executable: PathBuf,
        address: String,
    },
    Clash {
        client: reqwest::Client,
        base: String,
        secret: String,
    },
}

struct Session {
    children: Vec<Child>,
    job: Option<Job>,
    paths: Vec<PathBuf>,
    readers: Vec<JoinHandle<()>>,
    proxy: Option<Proxy>,
    api: Option<CoreApi>,
    started: Option<Instant>,
    state: CoreState,
}
impl Session {
    fn new(directory: &Path, probe: bool) -> Self {
        Self {
            children: Vec::new(),
            job: None,
            paths: Vec::new(),
            readers: Vec::new(),
            proxy: (!probe).then(|| Proxy::new(directory)),
            api: None,
            started: None,
            state: CoreState::default(),
        }
    }
    async fn stop(&mut self) -> Result<()> {
        if let Some(CoreApi::FlClash(mut core)) = self.api.take() {
            core.stop().await;
            drop(core);
            if let Some(child) = self.children.last_mut() {
                let _ = tokio::time::timeout(Duration::from_secs(2), child.wait()).await;
            }
        }
        self.job.take();
        for child in &mut self.children {
            let _ = child.kill().await;
            let _ = child.wait().await;
        }
        self.children.clear();
        for task in self.readers.drain(..) {
            task.abort();
            let _ = task.await;
        }
        let restore = self.proxy.as_mut().map(|p| p.restore()).transpose();
        for path in self.paths.drain(..) {
            let _ = fs::remove_file(path);
        }
        self.started = None;
        restore?;
        self.state = CoreState::default();
        Ok(())
    }
    async fn spawn(&mut self, exe: &Path, args: &[&str], log: &Log) -> Result<()> {
        let mut child = command(exe)
            .args(args)
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .map_err(|_| "Не удалось запустить процесс ядра.")?;
        self.job
            .as_ref()
            .ok_or("Job Object не создан.")?
            .assign(child.id().ok_or("Процесс ядра завершился.")?)?;
        if let Some(stdout) = child.stdout.take() {
            let log = log.clone();
            self.readers.push(tokio::spawn(async move {
                let mut lines = BufReader::new(stdout).lines();
                while let Ok(Some(line)) = lines.next_line().await {
                    log.lock().unwrap_or_else(|e| e.into_inner()).add(&line);
                }
            }));
        }
        if let Some(stderr) = child.stderr.take() {
            let log = log.clone();
            self.readers.push(tokio::spawn(async move {
                let mut lines = BufReader::new(stderr).lines();
                while let Ok(Some(line)) = lines.next_line().await {
                    log.lock().unwrap_or_else(|e| e.into_inner()).add(&line);
                }
            }));
        }
        self.children.push(child);
        Ok(())
    }
    fn config(
        &mut self,
        directory: &Path,
        label: &str,
        value: &Value,
        log: &Log,
    ) -> Result<PathBuf> {
        let path = directory.join(format!("session-{label}-{}.json", uuid::Uuid::new_v4()));
        self.write_config(&path, value, log)?;
        Ok(path)
    }
    fn write_config(&mut self, path: &Path, value: &Value, log: &Log) -> Result<()> {
        log.lock()
            .unwrap_or_else(|e| e.into_inner())
            .register(value);
        atomic_write(path, value.to_string().as_bytes())?;
        self.paths.push(path.to_owned());
        Ok(())
    }
    fn alive(&mut self) -> bool {
        self.children
            .iter_mut()
            .all(|c| matches!(c.try_wait(), Ok(None)))
    }
    async fn traffic(&mut self) -> Result<Stats> {
        if !self.alive() {
            return Err("Ядро аварийно завершилось. Соединение остановлено.".into());
        }
        let (upload, download) = match self.api.as_mut().ok_or("API ядра недоступен.")?
        {
            CoreApi::FlClash(core) => tokio::time::timeout(Duration::from_secs(2), core.traffic())
                .await
                .map_err(|_| "Потеряна связь с FlClashCore.")??,
            CoreApi::Xray {
                executable,
                address,
            } => xray_traffic(executable, address).await?,
            CoreApi::Clash {
                client,
                base,
                secret,
            } => {
                let response = client
                    .get(format!("{base}/connections"))
                    .bearer_auth(secret)
                    .timeout(Duration::from_secs(2))
                    .send()
                    .await
                    .and_then(reqwest::Response::error_for_status)
                    .map_err(|_| "Потеряна связь с ядром. Соединение остановлено.")?;
                let value: Value = response
                    .json()
                    .await
                    .map_err(|_| "Некорректная статистика ядра.")?;
                (
                    value["uploadTotal"]
                        .as_u64()
                        .ok_or("Некорректная статистика ядра.")?,
                    value["downloadTotal"]
                        .as_u64()
                        .ok_or("Некорректная статистика ядра.")?,
                )
            }
        };
        Ok(Stats {
            upload,
            download,
            duration: self.started.map_or(0, |time| time.elapsed().as_secs()),
        })
    }
}
impl Drop for Session {
    fn drop(&mut self) {
        self.api.take();
        self.job.take();
        for child in &mut self.children {
            let _ = child.start_kill();
        }
        for task in self.readers.drain(..) {
            task.abort();
        }
        if let Some(p) = self.proxy.as_mut() {
            let _ = p.restore();
        }
        for path in self.paths.drain(..) {
            let _ = fs::remove_file(path);
        }
    }
}
pub struct WindowsHost {
    directory: PathBuf,
    assets: PathBuf,
    session: Mutex<Session>,
    log: Log,
    probe: bool,
    _instance: Option<NativeHandle>,
}
impl WindowsHost {
    /// An independent loopback proxy used by latency checks and integration tests.
    /// It never changes WinINET, registers URLs, or restores another session.
    pub fn isolated_probe(directory: PathBuf, assets: PathBuf, log: Log) -> Self {
        Self {
            session: Mutex::new(Session::new(&directory, true)),
            directory,
            assets,
            log,
            probe: true,
            _instance: None,
        }
    }
    pub async fn new(directory: PathBuf, assets: PathBuf, log: Log) -> Result<Self> {
        let instance = single_instance(&directory)?;
        let runtime = directory.join("runtime");
        fs::create_dir_all(&runtime).map_err(|_| "Не удалось создать каталог приложения.")?;
        restore_proxy(&runtime.join("proxy.dpapi"))?;
        match fs::remove_file(runtime.join("flclash/config.yaml")) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return Err("Не удалось удалить старую конфигурацию FlClashCore.".into()),
        }
        for path in fs::read_dir(&runtime)
            .map_err(|_| "Не удалось открыть каталог приложения.")?
            .flatten()
            .map(|e| e.path())
            .filter(|p| {
                p.file_name()
                    .is_some_and(|s| s.to_string_lossy().starts_with("session-"))
                    && p.extension().is_some_and(|s| s == "json")
            })
        {
            fs::remove_file(path).map_err(|_| "Не удалось удалить старую конфигурацию.")?;
        }
        if std::env::var_os("LUNARIS_DATA_DIR").is_none() && register_protocol(&directory).is_err()
        {
            log.lock()
                .unwrap_or_else(|e| e.into_inner())
                .add("Не удалось зарегистрировать ссылки lunaris://.");
        }
        Ok(Self {
            session: Mutex::new(Session::new(&runtime, false)),
            directory: runtime,
            assets,
            log,
            probe: false,
            _instance: Some(instance),
        })
    }
    fn executable(&self, s: &Settings) -> PathBuf {
        let path = if s.core == "mihomo" {
            &s.mihomo_path
        } else {
            &s.core_path
        };
        if path.is_empty() {
            self.assets.join("core").join(if s.core == "mihomo" {
                "mihomo.exe"
            } else {
                "sing-box.exe"
            })
        } else {
            PathBuf::from(path)
        }
    }
    async fn start_xray(
        &self,
        session: &mut Session,
        exe: &Path,
        profile: &Profile,
        settings: &Settings,
        hosts: Option<&Value>,
    ) -> Result<()> {
        let verify_port = (!self.probe && settings.verify_connection)
            .then(|| free_port(&[settings.mixed_port, settings.api_port]))
            .transpose()?;
        let config = config::xray_desktop(profile, settings, hosts, verify_port)?;
        if settings.mode == "tun" && !exe.with_file_name("wintun.dll").is_file() {
            return Err("Для TUN в режиме Xray нужен wintun.dll из комплекта ядер.".into());
        }
        check_xray(exe, &self.log).await?;
        let path = session.config(&self.directory, "xray", &config, &self.log)?;
        let path = path.to_string_lossy();
        checked(exe, &["run", "-test", "-c", &path], &self.log).await?;
        session.spawn(exe, &["run", "-c", &path], &self.log).await?;
        let api = format!("127.0.0.1:{}", settings.api_port);
        let deadline = Instant::now() + Duration::from_secs(12);
        loop {
            if !session.alive() {
                return Err("Xray завершился во время запуска. Проверьте журнал.".into());
            }
            if tokio::net::TcpStream::connect(("127.0.0.1", settings.mixed_port))
                .await
                .is_ok()
                && xray_traffic(exe, &api).await.is_ok()
            {
                break;
            }
            if Instant::now() > deadline {
                return Err("Xray не открыл локальный прокси и API статистики.".into());
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        if let Some(port) = verify_port {
            let mut verification = settings.clone();
            verification.mixed_port = port;
            if latency::proxy(&verification).await.error.is_some() {
                return Err("Сервер не прошёл проверку HTTPS через Xray.".into());
            }
        }
        session.api = Some(CoreApi::Xray {
            executable: exe.to_owned(),
            address: api,
        });
        Ok(())
    }
    async fn start_flclash(
        &self,
        session: &mut Session,
        exe: &Path,
        profile: &Profile,
        settings: &Settings,
        hosts: Option<&Value>,
    ) -> Result<()> {
        let home = if self.probe {
            self.directory.clone()
        } else {
            self.directory.join("flclash")
        };
        fs::create_dir_all(&home).map_err(|_| "Не удалось создать каталог FlClashCore.")?;
        let mut config = config::mihomo(profile, settings, "", hosts)?;
        if let Some(map) = config.as_object_mut() {
            map.remove("external-controller");
            map.remove("secret");
        }
        session.write_config(&home.join("config.yaml"), &config, &self.log)?;
        let address = format!(r"\\.\pipe\LunarisCore-{}", uuid::Uuid::new_v4());
        let pipe = ServerOptions::new()
            .first_pipe_instance(true)
            .reject_remote_clients(true)
            .create(&address)
            .map_err(|_| "Не удалось создать именованный канал FlClashCore.")?;
        session.spawn(exe, &[&address], &self.log).await?;
        let pid = session
            .children
            .last()
            .and_then(Child::id)
            .ok_or("FlClashCore завершился.")?;
        let mut core = flclash::Core::accept(pipe, pid, self.log.clone()).await?;
        core.start(&home, &settings.probe_url).await?;
        if tokio::net::TcpStream::connect(("127.0.0.1", settings.mixed_port))
            .await
            .is_err()
        {
            return Err("FlClashCore не открыл локальный прокси.".into());
        }
        if !self.probe && settings.verify_connection {
            if let Err(error) = core.check(&settings.probe_url).await {
                core.stop().await;
                return Err(error);
            }
        }
        session.api = Some(CoreApi::FlClash(core));
        Ok(())
    }

    fn connected(&self, session: &mut Session, settings: &Settings) -> Result<CoreState> {
        if settings.mode == "proxy" {
            if let Some(proxy) = session.proxy.as_mut() {
                proxy.apply(settings.mixed_port)?;
            }
        }
        session.started = Some(Instant::now());
        session.state = CoreState {
            status: "connected".into(),
            ..Default::default()
        };
        Ok(session.state.clone())
    }
    async fn start(
        &self,
        session: &mut Session,
        p: &Profile,
        settings: &Settings,
    ) -> Result<CoreState> {
        settings.validate()?;
        let mut settings = settings.clone();
        if p.xray_grpc() && settings.core == "mihomo" {
            settings.core = "sing-box".into();
            self.log.lock().unwrap_or_else(|e|e.into_inner()).add("gRPC mode=multi или authority требует Xray; для этого соединения используется sing-box / Xray.");
        }
        let s = &settings;
        let mihomo = s.core == "mihomo";
        let flclash = mihomo && s.mihomo_path.is_empty();
        let exe = match s.core.as_str() {
            "xray" => self.assets.join("core/xray.exe"),
            "mihomo" if flclash => self.assets.join("core/FlClashCore.exe"),
            _ => self.executable(s),
        };
        if !exe.is_file() {
            return Err(
                "Ядро не найдено. Проверьте комплект приложения или путь в настройках.".into(),
            );
        }
        if s.mode == "tun" && unsafe { windows_sys::Win32::UI::Shell::IsUserAnAdmin() } == 0 {
            return Err("TUN требует запуска приложения от имени администратора.".into());
        }
        let a = std::net::TcpListener::bind(("127.0.0.1", s.mixed_port))
            .map_err(|_| "Локальный порт занят. Измените порты в настройках.")?;
        if !flclash {
            std::net::TcpListener::bind(("127.0.0.1", s.api_port))
                .map_err(|_| "Локальный порт управления занят.")?;
        }
        drop(a);
        let hosts = if s.mode == "tun" {
            Some(resolve(p, s, &self.log).await?)
        } else {
            None
        };
        restrict(&self.directory).await?;
        session.job = Some(Job::new()?);
        if s.core == "xray" {
            self.start_xray(session, &exe, p, s, hosts.as_ref()).await?;
            return self.connected(session, s);
        }
        if flclash {
            self.start_flclash(session, &exe, p, s, hosts.as_ref())
                .await?;
            return self.connected(session, s);
        }
        let version = checked(&exe, &[if mihomo { "-v" } else { "version" }], &self.log).await?;
        if if mihomo {
            !version.starts_with(&format!("Mihomo Meta v{} ", crate::MIHOMO))
        } else {
            !version
                .replace("\r\n", "\n")
                .contains(&format!("sing-box version {}\n", crate::SING_BOX))
        } {
            return Err("Версия ядра не совпадает с проверенным комплектом приложения.".into());
        }
        let secret = secret();
        let config = if mihomo {
            config::mihomo(p, s, &secret, hosts.as_ref())?
        } else {
            let sidecar = if let Some(mut config) =
                config::xray_for_sing_box(p, &secret, s, hosts.as_ref())?
            {
                let port = free_port(&[s.mixed_port, s.api_port])?;
                config["inbounds"][0]["port"] = json!(port);
                let adjacent = exe.parent().unwrap_or(&self.assets).join("xray.exe");
                let xray = if adjacent.is_file() {
                    adjacent
                } else {
                    self.assets.join("core/xray.exe")
                };
                check_xray(&xray, &self.log).await?;
                let password = secret.clone();
                let path = session.config(&self.directory, "xray", &config, &self.log)?;
                let path = path.to_string_lossy().to_string();
                checked(&xray, &["run", "-test", "-c", &path], &self.log).await?;
                session
                    .spawn(&xray, &["run", "-c", &path], &self.log)
                    .await?;
                let deadline = Instant::now() + Duration::from_secs(10);
                loop {
                    if !session.alive() {
                        return Err("Xray завершился во время запуска.".into());
                    }
                    if tokio::net::TcpStream::connect(("127.0.0.1", port))
                        .await
                        .is_ok()
                    {
                        break;
                    }
                    if Instant::now() > deadline {
                        return Err("Xray не открыл локальный порт.".into());
                    }
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
                Some(config::sidecar(port, &password))
            } else {
                None
            };
            config::sing_box(p, s, &secret, false, sidecar, hosts.as_ref())?
        };
        let path = session.config(&self.directory, "main", &config, &self.log)?;
        let path = path.to_string_lossy().to_string();
        let directory = self.directory.to_string_lossy().to_string();
        if mihomo {
            checked(&exe, &["-t", "-d", &directory, "-f", &path], &self.log).await?;
            session
                .spawn(&exe, &["-d", &directory, "-f", &path], &self.log)
                .await?;
        } else {
            checked(&exe, &["check", "-c", &path], &self.log).await?;
            session
                .spawn(&exe, &["run", "-c", &path], &self.log)
                .await?;
        }
        let client = reqwest::Client::builder()
            .no_proxy()
            .timeout(Duration::from_secs(15))
            .build()
            .map_err(|_| "Не удалось открыть API ядра.")?;
        let api = format!("http://127.0.0.1:{}", s.api_port);
        let deadline = Instant::now() + Duration::from_secs(12);
        loop {
            if !session.alive() {
                return Err("Ядро завершилось во время запуска. Проверьте журнал.".into());
            }
            let ready = client
                .get(format!("{api}/version"))
                .bearer_auth(&secret)
                .timeout(Duration::from_secs(1))
                .send()
                .await
                .is_ok_and(|r| r.status().is_success());
            if ready
                && tokio::net::TcpStream::connect(("127.0.0.1", s.mixed_port))
                    .await
                    .is_ok()
            {
                break;
            }
            if Instant::now() > deadline {
                return Err(
                    "Ядро не подтвердило запуск API управления и локального прокси.".into(),
                );
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        if !self.probe && s.verify_connection {
            let response = client
                .get(format!("{api}/proxies/proxy/delay"))
                .bearer_auth(&secret)
                .query(&[("url", s.probe_url.as_str()), ("timeout", "10000")])
                .send()
                .await
                .map_err(|_| "Сервер не прошёл проверку HTTPS через ядро.")?;
            if !response.status().is_success()
                || response
                    .json::<Value>()
                    .await
                    .ok()
                    .and_then(|v| v["delay"].as_f64())
                    .is_none()
            {
                return Err(
                    "Сервер не прошёл проверку HTTPS через ядро. Подключение не подтверждено."
                        .into(),
                );
            }
        }
        session.api = Some(CoreApi::Clash {
            client,
            base: api,
            secret,
        });
        self.connected(session, s)
    }
}

async fn check_xray(exe: &Path, log: &Log) -> Result<()> {
    let version = checked(exe, &["version"], log).await?;
    if !version.starts_with(&format!("Xray {} ", crate::XRAY)) {
        return Err(format!(
            "Нужен Xray {} из проверенного комплекта ядер.",
            crate::XRAY
        ));
    }
    Ok(())
}

async fn xray_traffic(exe: &Path, api: &str) -> Result<(u64, u64)> {
    let mut command = command(exe);
    command.args([
        "api",
        "statsquery",
        "-s",
        api,
        "-t",
        "1",
        "-pattern",
        "inbound>>>",
    ]);
    let output = tokio::time::timeout(Duration::from_secs(2), command.output())
        .await
        .ok()
        .and_then(std::result::Result::ok)
        .filter(|output| output.status.success())
        .ok_or("Потеряна связь с API статистики Xray.")?;
    let value: Value =
        serde_json::from_slice(&output.stdout).map_err(|_| "Некорректная статистика Xray.")?;
    let mut upload: u64 = 0;
    let mut download: u64 = 0;
    if let Some(stats) = value["stat"].as_array() {
        for stat in stats {
            let amount = stat["value"]
                .as_u64()
                .or_else(|| stat["value"].as_str()?.parse().ok())
                .unwrap_or(0);
            let name = stat["name"].as_str().unwrap_or_default();
            if name.ends_with(">>>traffic>>>uplink") {
                upload = upload.saturating_add(amount);
            } else if name.ends_with(">>>traffic>>>downlink") {
                download = download.saturating_add(amount);
            }
        }
    }
    Ok((upload, download))
}
#[async_trait]
impl Host for WindowsHost {
    async fn encrypt(&self, data: &[u8]) -> Result<Vec<u8>> {
        dpapi(data, false)
    }
    async fn decrypt(&self, data: &[u8]) -> Result<Vec<u8>> {
        dpapi(data, true)
    }
    async fn connect(&self, p: &Profile, s: &Settings) -> Result<CoreState> {
        let mut session = self.session.lock().await;
        session.stop().await?;
        match self.start(&mut session, p, s).await {
            Ok(s) => Ok(s),
            Err(e) => {
                let cleanup = session.stop().await;
                session.state = CoreState {
                    status: "error".into(),
                    error: Some(cleanup.err().unwrap_or(e)),
                    stats: Default::default(),
                };
                Err(session.state.error.clone().unwrap())
            }
        }
    }
    async fn disconnect(&self) -> Result<CoreState> {
        let mut session = self.session.lock().await;
        session.stop().await?;
        Ok(session.state.clone())
    }
    async fn snapshot(&self) -> Result<CoreState> {
        let mut session = self.session.lock().await;
        if session.state.status == "connected" {
            match session.traffic().await {
                Ok(stats) => session.state.stats = stats,
                Err(e) => {
                    let cleanup = session.stop().await;
                    session.state = CoreState {
                        status: "error".into(),
                        error: Some(cleanup.err().unwrap_or(e)),
                        stats: Default::default(),
                    };
                }
            }
        }
        Ok(session.state.clone())
    }
    async fn take_import_link(&self) -> Result<Value> {
        let directory = self.directory.parent().unwrap_or(&self.directory);
        take_import_link(directory)
    }
    async fn open_update_url(&self, url: &str) -> Result<()> {
        crate::updates::validate_download_url(url)?;
        let url = wide(url);
        let result = unsafe {
            windows_sys::Win32::UI::Shell::ShellExecuteW(
                std::ptr::null_mut(),
                wide("open").as_ptr(),
                url.as_ptr(),
                std::ptr::null(),
                std::ptr::null(),
                windows_sys::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL,
            )
        };
        if result as isize <= 32 {
            return Err("Не удалось открыть браузер для скачивания обновления.".into());
        }
        Ok(())
    }
    async fn probe(&self, p: &Profile, s: &Settings) -> Latency {
        let directory = self
            .directory
            .join(format!("probe-{}", uuid::Uuid::new_v4()));
        let mut settings = s.clone();
        settings.mode = "proxy".into();
        let Ok(port) = free_port(&[]) else {
            return Latency::error("Нет свободного порта");
        };
        settings.mixed_port = port;
        let Ok(port) = free_port(&[port]) else {
            return Latency::error("Нет свободного порта");
        };
        settings.api_port = port;
        let host = WindowsHost::isolated_probe(
            directory.clone(),
            self.assets.clone(),
            Arc::new(std::sync::Mutex::new(Default::default())),
        );
        let result = tokio::time::timeout(Duration::from_secs(30), async {
            host.connect(p, &settings).await?;
            Ok::<_, String>(latency::proxy(&settings).await)
        })
        .await;
        let _ = host.disconnect().await;
        let _ = fs::remove_dir(&directory);
        match result {
            Ok(Ok(result)) => result,
            _ => Latency::error("Прокси сервера недоступен"),
        }
    }
}
async fn resolve(p: &Profile, s: &Settings, _log: &Log) -> Result<Value> {
    let name = p.outbound["server"]
        .as_str()
        .ok_or("Некорректный адрес сервера.")?;
    if name.parse::<std::net::IpAddr>().is_ok() {
        return Ok(json!({}));
    }
    Ok(json!({name:crate::bootstrap::resolve(name,&s.bootstrap_dns,s.ipv6).await?}))
}
fn register_protocol(_directory: &Path) -> Result<()> {
    let executable = std::env::current_exe().map_err(|_| "Не найден исполняемый файл.")?;
    let (key, _) = RegKey::predef(HKEY_CURRENT_USER)
        .create_subkey(r"Software\Classes\lunaris")
        .map_err(|_| "Не удалось зарегистрировать URL-протокол.")?;
    key.set_value("", &"URL:Lunaris client")
        .map_err(|_| "Не удалось зарегистрировать URL-протокол.")?;
    key.set_value("URL Protocol", &"")
        .map_err(|_| "Не удалось зарегистрировать URL-протокол.")?;
    let (action, _) = key
        .create_subkey(r"shell\open\command")
        .map_err(|_| "Не удалось зарегистрировать URL-протокол.")?;
    let command = format!("\"{}\" --import-link \"%1\"", executable.display());
    action
        .set_value("", &command)
        .map_err(|_| "Не удалось зарегистрировать URL-протокол.".into())
}
pub fn import_from_args() -> bool {
    let args = std::env::args().collect::<Vec<_>>();
    if args.get(1).is_none_or(|v| v != "--import-link") {
        return false;
    }
    let Some(link) = args
        .get(2)
        .filter(|s| s.len() <= 25000 && s.to_lowercase().starts_with("lunaris://"))
    else {
        return true;
    };
    let directory = std::env::var_os("LUNARIS_DATA_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            PathBuf::from(std::env::var_os("LOCALAPPDATA").unwrap_or_default()).join("SeverVPN")
        });
    let inbox = directory.join("imports");
    let save = || -> Result<()> {
        fs::create_dir_all(&inbox).map_err(|_| "Не удалось создать каталог импорта.")?;
        let name = format!(
            "{:020}-{}.link",
            (timestamp() * 1000.) as u64,
            uuid::Uuid::new_v4()
        );
        atomic_write(&inbox.join(name), &dpapi(link.as_bytes(), false)?)?;
        Ok(())
    };
    if save().is_err() {
        return true;
    }
    let mutex = unsafe { OpenMutexW(0x00100000, 0, wide("Local\\SeverVPN").as_ptr()) };
    if mutex.is_null() {
        if let Ok(exe) = std::env::current_exe() {
            use std::os::windows::process::CommandExt;
            let _ = std::process::Command::new(exe)
                .creation_flags(0x08000000)
                .spawn();
        }
    } else {
        drop(NativeHandle(mutex as usize));
    }
    true
}
fn take_import_link(directory: &Path) -> Result<Value> {
    let Ok(entries) = fs::read_dir(directory.join("imports")) else {
        return Ok(Value::Null);
    };
    let mut paths = entries
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|s| s == "link"))
        .collect::<Vec<_>>();
    paths.sort();
    for path in paths {
        let result = (|| {
            let meta = path.metadata().ok()?;
            if meta.len() > 100000 || meta.modified().ok()?.elapsed().ok()?.as_secs() > 120 {
                return None;
            }
            let plain = dpapi(&fs::read(&path).ok()?, true).ok()?;
            String::from_utf8(plain).ok()
        })();
        let _ = fs::remove_file(&path);
        if let Some(link) = result {
            return Ok(json!(link));
        }
    }
    Ok(Value::Null)
}
