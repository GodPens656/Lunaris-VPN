use crate::{
    config,
    latency::{self, Latency},
    models::*,
    parser,
    redaction::SafeLog,
    storage::Repository,
    subscriptions, updates, Result,
};
use async_trait::async_trait;
use futures_util::{stream, StreamExt};
use rand::RngCore;
use serde_json::{json, Value};
use std::{
    collections::{BTreeMap, HashSet},
    path::PathBuf,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex as StdMutex,
    },
    time::Duration,
};
use tokio::{sync::Mutex, task::JoinHandle};
pub type Log = Arc<StdMutex<SafeLog>>;

#[async_trait]
pub trait Host: Send + Sync {
    fn android(&self) -> bool {
        false
    }
    async fn encrypt(&self, data: &[u8]) -> Result<Vec<u8>>;
    async fn decrypt(&self, data: &[u8]) -> Result<Vec<u8>>;
    async fn connect(&self, profile: &Profile, settings: &Settings) -> Result<CoreState>;
    async fn disconnect(&self) -> Result<CoreState>;
    async fn snapshot(&self) -> Result<CoreState>;
    async fn take_import_link(&self) -> Result<Value> {
        Ok(Value::Null)
    }
    async fn open_update_url(&self, _url: &str) -> Result<()> {
        Err("Не удалось открыть загрузку обновления.".into())
    }
    async fn probe(&self, _profile: &Profile, _settings: &Settings) -> Latency {
        Latency::error("Проверка через прокси недоступна")
    }
}
pub fn secret() -> String {
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}
struct Inner {
    repo: Repository,
    core: CoreState,
    active: Option<String>,
    results: BTreeMap<String, Latency>,
    measure_total: usize,
}
pub struct Engine {
    inner: Mutex<Inner>,
    host: Arc<dyn Host>,
    pub log: Log,
    gate: Mutex<()>,
    subscription_gate: Mutex<()>,
    connector: Mutex<Option<JoinHandle<()>>>,
    measurement: Mutex<Option<JoinHandle<()>>>,
    scheduler: Mutex<Option<JoinHandle<()>>>,
    monitor: Mutex<Option<JoinHandle<()>>>,
    closed: AtomicBool,
    available_update: Mutex<Option<updates::Update>>,
    update_check_gate: Mutex<()>,
}
impl Engine {
    pub async fn new(directory: PathBuf, host: Arc<dyn Host>, log: Log) -> Result<Arc<Self>> {
        let mut repo = Repository::open(directory, host.clone()).await?;
        // Desktop 0.6.0 selected Mihomo on first launch; retain that default.
        if !repo.directory.join("state.enc").exists() && !host.android() {
            repo.state.settings.core = "mihomo".into();
        }
        let core = if host.android() {
            host.snapshot().await?
        } else {
            CoreState::default()
        };
        let e = Arc::new(Self {
            inner: Mutex::new(Inner {
                repo,
                core,
                active: None,
                results: BTreeMap::new(),
                measure_total: 0,
            }),
            host,
            log,
            gate: Mutex::new(()),
            subscription_gate: Mutex::new(()),
            connector: Mutex::new(None),
            measurement: Mutex::new(None),
            scheduler: Mutex::new(None),
            monitor: Mutex::new(None),
            closed: AtomicBool::new(false),
            available_update: Mutex::new(None),
            update_check_gate: Mutex::new(()),
        });
        let weak = Arc::downgrade(&e);
        let startup = {
            let i = e.inner.lock().await;
            if i.repo.state.settings.update_on_start {
                i.repo
                    .state
                    .subscriptions
                    .iter()
                    .map(|s| s.id.clone())
                    .collect::<Vec<_>>()
            } else {
                Vec::new()
            }
        };
        *e.scheduler.lock().await = Some(tokio::spawn(async move {
            let mut first = true;
            let mut last = timestamp();
            loop {
                let Some(e) = weak.upgrade() else {
                    return;
                };
                if e.closed.load(Ordering::SeqCst) {
                    return;
                }
                let due = {
                    let i = e.inner.lock().await;
                    let s = &i.repo.state.settings;
                    i.repo
                        .state
                        .subscriptions
                        .iter()
                        .filter(|sub| {
                            if first {
                                startup.contains(&sub.id)
                            } else {
                                s.update_minutes > 0
                                    && timestamp() - last >= s.update_minutes as f64 * 60.
                            }
                        })
                        .map(|s| s.id.clone())
                        .collect::<Vec<_>>()
                };
                first = false;
                if !due.is_empty() {
                    last = timestamp();
                }
                for id in due {
                    if e.closed.load(Ordering::SeqCst) {
                        return;
                    }
                    let _ = e.update_subscription(&id).await;
                }
                drop(e);
                tokio::time::sleep(Duration::from_secs(30)).await;
            }
        }));
        if !e.host.android() {
            let weak = Arc::downgrade(&e);
            *e.monitor.lock().await = Some(tokio::spawn(async move {
                loop {
                    tokio::time::sleep(Duration::from_secs(1)).await;
                    let Some(e) = weak.upgrade() else {
                        return;
                    };
                    if e.closed.load(Ordering::SeqCst) {
                        return;
                    }
                    e.refresh().await;
                }
            }));
        }
        Ok(e)
    }
    pub async fn snapshot(&self) -> Value {
        let measuring = self
            .measurement
            .lock()
            .await
            .as_ref()
            .is_some_and(|t| !t.is_finished());
        let i = self.inner.lock().await;
        let state = &i.repo.state;
        json!({"version":crate::VERSION,"platform":if self.host.android(){"android"}else{"windows"},"cores":{"sing-box":crate::SING_BOX,"mihomo":crate::MIHOMO},"status":i.core.status,"error":i.core.error,"stats":i.core.stats,"selected":state.selected,"active":i.active,"settings":state.settings,
            "profiles":state.profiles.iter().map(|p|json!({"key":p.key(),"name":p.name,"protocol":p.protocol(),"source_id":p.source_id})).collect::<Vec<_>>(),
            "subscriptions":state.subscriptions.iter().map(|s|json!({"id":s.id,"name":s.name,"description":s.description,"error":s.error,"last_success":s.last_success,"userinfo":s.userinfo,"count":state.profiles.iter().filter(|p|p.source_id.as_ref()==Some(&s.id)).count(),"rejected":s.rejected.len(),"duplicates":s.duplicates})).collect::<Vec<_>>(),
            "logs":self.log.lock().unwrap_or_else(|e|e.into_inner()).lines,"latency":i.results,"measuring":measuring,"measure_total":i.measure_total})
    }
    async fn refresh(&self) {
        let Ok(_gate) = self.gate.try_lock() else {
            return;
        };
        if self
            .connector
            .lock()
            .await
            .as_ref()
            .is_some_and(|t| !t.is_finished())
        {
            return;
        }
        match self.host.snapshot().await {
            Ok(core) => {
                let mut i = self.inner.lock().await;
                if core.error != i.core.error {
                    if let Some(error) = &core.error {
                        self.log
                            .lock()
                            .unwrap_or_else(|e| e.into_inner())
                            .add(error);
                    }
                }
                i.core = core;
                if i.core.status == "disconnected" {
                    i.active = None;
                }
            }
            Err(error) => {
                let mut i = self.inner.lock().await;
                i.core.status = "error".into();
                i.core.error = Some(error);
            }
        }
    }
    async fn cancel_measurement(&self) {
        if let Some(task) = self.measurement.lock().await.take() {
            task.abort();
            let _ = task.await;
        }
    }
    async fn disconnect(&self) -> Result<()> {
        self.cancel_measurement().await;
        if let Some(task) = self.connector.lock().await.take() {
            task.abort();
            let _ = task.await;
        }
        self.inner.lock().await.core.status = "disconnecting".into();
        let result = self.host.disconnect().await;
        let mut i = self.inner.lock().await;
        match result {
            Ok(core) => {
                let stopped = core.status == "disconnected";
                let error = core.error.clone();
                i.core = core;
                if stopped {
                    i.active = None;
                    Ok(())
                } else {
                    Err(error.unwrap_or(
                        "Не удалось завершить подключение. Повторите отключение.".into(),
                    ))
                }
            }
            Err(error) => {
                i.core.status = "error".into();
                i.core.error = Some(error.clone());
                Err(error)
            }
        }
    }
    async fn connect(self: &Arc<Self>) -> Result<()> {
        self.cancel_measurement().await;
        let (p, s) = {
            let mut i = self.inner.lock().await;
            let p = i
                .repo
                .state
                .profiles
                .iter()
                .find(|p| Some(p.key()) == i.repo.state.selected)
                .cloned()
                .ok_or("Добавьте подписку или импортируйте сервер.")?;
            let settings = i.repo.state.settings.clone();
            i.active = Some(p.key());
            i.core = CoreState {
                status: "connecting".into(),
                ..Default::default()
            };
            (p, settings)
        };
        let e = self.clone();
        *self.connector.lock().await = Some(tokio::spawn(async move {
            let result = e.host.connect(&p, &s).await;
            let mut i = e.inner.lock().await;
            match result {
                Ok(core) => i.core = core,
                Err(error) => {
                    e.log.lock().unwrap_or_else(|e| e.into_inner()).add(&error);
                    i.core.status = "error".into();
                    i.core.error = Some(error);
                }
            }
        }));
        Ok(())
    }
    async fn update_subscription(&self, id: &str) -> Result<()> {
        // Serialize refreshes without blocking VPN commands during network I/O.
        let _subscription_gate = self.subscription_gate.lock().await;
        if self.closed.load(Ordering::SeqCst) {
            return Err("Приложение завершает работу.".into());
        }
        let url = {
            let i = self.inner.lock().await;
            i.repo
                .state
                .subscriptions
                .iter()
                .find(|s| s.id == id)
                .map(|s| s.url.clone())
                .ok_or("Подписка уже удалена.")?
        };
        let result: Result<_> = async {
            let fetched = subscriptions::fetch(&url).await?;
            let source = id.to_string();
            tokio::task::spawn_blocking(move || -> Result<_> {
                let report = parser::parse_subscription(&fetched.body, Some(&source))?;
                Ok((report, fetched))
            })
            .await
            .map_err(|_| "Не удалось обработать подписку.".to_string())?
        }
        .await;
        // Merge into the latest state: selection/settings/deletion can change
        // while the subscription is downloading.
        let _gate = self.gate.lock().await;
        if self.closed.load(Ordering::SeqCst) {
            return Err("Приложение завершает работу.".into());
        }
        let mut i = self.inner.lock().await;
        let mut state = i.repo.state.clone();
        if !state.subscriptions.iter().any(|s| s.id == id) {
            return Err("Подписка удалена во время обновления.".into());
        }
        match result {
            Ok((report, fetched)) => {
                if report.profiles.is_empty() {
                    let error = "В обновлении нет валидных серверов. Предыдущие серверы сохранены."
                        .to_string();
                    if let Some(target) = state.subscriptions.iter_mut().find(|s| s.id == id) {
                        target.error = Some(error.clone());
                        target.rejected = report.rejected;
                        target.duplicates = report.duplicates;
                        i.repo.commit(state).await?;
                    }
                    return Err(error);
                }
                let rejected = report.rejected;
                let duplicates = report.duplicates;
                subscriptions::replace_profiles(&mut state, id, report.profiles);
                let target = state
                    .subscriptions
                    .iter_mut()
                    .find(|s| s.id == id)
                    .ok_or("Подписка удалена во время обновления.")?;
                target.last_success = Some(timestamp());
                target.error = None;
                target.userinfo = fetched.userinfo;
                target.description = fetched.description;
                target.rejected = rejected;
                target.duplicates = duplicates;
                if target.auto_name {
                    if let Some(name) = fetched.title {
                        target.name = name;
                    }
                }
                i.repo.commit(state).await
            }
            Err(error) => {
                if let Some(s) = state.subscriptions.iter_mut().find(|s| s.id == id) {
                    s.error = Some(error.clone());
                    i.repo.commit(state).await?;
                }
                Err(error)
            }
        }
    }
    pub async fn dispatch(self: &Arc<Self>, method: &str, args: Value) -> Result<Value> {
        if !args.is_object() {
            return Err("Некорректный запрос интерфейса.".into());
        }
        if serde_json::to_vec(&args).map_or(true, |s| s.len() > parser::MAX_BODY + 65536) {
            return Err("Данные запроса слишком большие.".into());
        }
        if self.closed.load(Ordering::SeqCst) && method != "shutdown" {
            return Err("Приложение завершает работу.".into());
        }
        if method == "snapshot" {
            self.refresh().await;
            return Ok(self.snapshot().await);
        }
        if method == "take_import_link" {
            return self.host.take_import_link().await;
        }
        if method == "check_app_update" {
            let _check = self.update_check_gate.lock().await;
            let update = updates::check(self.host.android()).await?;
            let value = serde_json::to_value(&update)
                .map_err(|_| "Не удалось прочитать сведения об обновлении.")?;
            *self.available_update.lock().await = update;
            return Ok(value);
        }
        if method == "download_app_update" {
            let update = self
                .available_update
                .lock()
                .await
                .clone()
                .ok_or("Сначала проверьте наличие обновления приложения.")?;
            if args["version"].as_str() != Some(update.version.as_str()) {
                return Err("Версия обновления изменилась. Проверьте обновление ещё раз.".into());
            }
            updates::validate_download_url(&update.download_url)?;
            self.host.open_update_url(&update.download_url).await?;
            return Ok(Value::Null);
        }
        if method == "shutdown" {
            self.shutdown().await?;
            return Ok(self.snapshot().await);
        }
        let string = |key: &str| args[key].as_str().unwrap_or("").to_string();
        // Downloading and parsing must not hold the shared command gate.
        if method == "update_subscription" {
            self.update_subscription(&string("id")).await?;
            return Ok(self.snapshot().await);
        }
        if method == "update_all" {
            let ids = self
                .inner
                .lock()
                .await
                .repo
                .state
                .subscriptions
                .iter()
                .map(|s| s.id.clone())
                .collect::<Vec<_>>();
            for id in ids {
                let _ = self.update_subscription(&id).await;
            }
            return Ok(self.snapshot().await);
        }
        let _gate = self.gate.lock().await;
        if self.closed.load(Ordering::SeqCst) {
            return Err("Приложение завершает работу.".into());
        }
        match method {
            "connect"
            | "toggle"
            | "disconnect"
            | "select"
            | "remove_profile"
            | "remove_subscription" => {
                let (running, selected, active) = {
                    let i = self.inner.lock().await;
                    (
                        matches!(
                            i.core.status.as_str(),
                            "connecting" | "connected" | "disconnecting"
                        ),
                        i.repo.state.selected.clone(),
                        i.active.clone(),
                    )
                };
                match method {
                    "connect" => {
                        if !running {
                            self.connect().await?;
                        }
                    }
                    "toggle" => {
                        if running {
                            self.disconnect().await?;
                        } else {
                            self.connect().await?;
                        }
                    }
                    "disconnect" => self.disconnect().await?,
                    "select" => {
                        let key = string("key");
                        if selected.as_ref() != Some(&key) {
                            let mut i = self.inner.lock().await;
                            if !i.repo.state.profiles.iter().any(|p| p.key() == key) {
                                return Err("Сервер уже удалён.".into());
                            }
                            let mut state = i.repo.state.clone();
                            state.selected = Some(key);
                            i.repo.commit(state).await?;
                            drop(i);
                            self.cancel_measurement().await;
                            if running {
                                self.disconnect().await?;
                                self.connect().await?;
                            }
                        }
                    }
                    _ => {
                        let target = if method == "remove_profile" {
                            string("key")
                        } else {
                            string("id")
                        };
                        let active_removed = {
                            let i = self.inner.lock().await;
                            i.repo.state.profiles.iter().any(|p| {
                                Some(p.key()) == active
                                    && if method == "remove_profile" {
                                        p.key() == target
                                    } else {
                                        p.source_id.as_ref() == Some(&target)
                                    }
                            })
                        };
                        if running && active_removed {
                            self.disconnect().await?;
                        }
                        self.cancel_measurement().await;
                        let mut i = self.inner.lock().await;
                        let mut state = i.repo.state.clone();
                        if method == "remove_profile" {
                            state
                                .profiles
                                .retain(|p| p.key() != target || p.source_id.is_some());
                        } else {
                            state.subscriptions.retain(|s| s.id != target);
                            state
                                .profiles
                                .retain(|p| p.source_id.as_ref() != Some(&target));
                        }
                        if !state
                            .profiles
                            .iter()
                            .any(|p| Some(p.key()) == state.selected)
                        {
                            state.selected = state.profiles.first().map(Profile::key);
                        }
                        i.repo.commit(state).await?;
                    }
                }
            }
            "import" => {
                let report = parser::import(&string("text"))?;
                let mut i = self.inner.lock().await;
                let mut state = i.repo.state.clone();
                let mut seen: HashSet<_> = state
                    .profiles
                    .iter()
                    .filter(|p| p.source_id.is_none())
                    .map(Profile::identity)
                    .collect();
                let mut imported = 0;
                let mut duplicates = report.duplicates;
                for p in report.profiles {
                    if seen.insert(p.identity()) {
                        state.profiles.push(p);
                        imported += 1;
                    } else {
                        duplicates += 1;
                    }
                }
                if state.selected.is_none() {
                    state.selected = state.profiles.first().map(Profile::key);
                }
                i.repo.commit(state).await?;
                drop(i);
                return Ok(
                    json!({"snapshot":self.snapshot().await,"imported":imported,"rejected":report.rejected,"duplicates":duplicates}),
                );
            }
            "settings" => {
                let mut i = self.inner.lock().await;
                let mut state = i.repo.state.clone();
                let mut settings = serde_json::to_value(&state.settings).unwrap();
                for (k, v) in args.as_object().unwrap() {
                    if settings.get(k).is_none() {
                        return Err("Неизвестная настройка.".into());
                    }
                    settings[k] = v.clone();
                }
                if self.host.android() {
                    settings["mode"] = json!("tun");
                }
                state.settings =
                    serde_json::from_value(settings).map_err(|_| "Некорректный тип настройки.")?;
                state.settings.bypass_domains = state.settings.normalized_bypass_domains()?;
                state.settings.validate()?;
                i.repo.commit(state).await?;
                drop(i);
                self.cancel_measurement().await;
            }
            "add_subscription" => {
                let mut url = string("url").trim().to_string();
                if url.to_lowercase().starts_with("lunaris:") {
                    url = subscriptions::subscription_url(&url)?;
                }
                let parsed = subscriptions::validate_url(&url)?;
                let name = string("name").trim().chars().take(100).collect::<String>();
                let id = uuid::Uuid::new_v4().to_string();
                let sub = Subscription {
                    id: id.clone(),
                    auto_name: name.is_empty(),
                    name: if name.is_empty() {
                        parsed.host_str().unwrap_or("Подписка").into()
                    } else {
                        name
                    },
                    url,
                    userinfo: json!({}),
                    ..Default::default()
                };
                let mut i = self.inner.lock().await;
                let mut state = i.repo.state.clone();
                state.subscriptions.push(sub);
                i.repo.commit(state).await?;
                drop(i);
                drop(_gate);
                self.update_subscription(&id).await?;
                return Ok(self.snapshot().await);
            }
            "cancel_measure" => self.cancel_measurement().await,
            "measure" => {
                self.cancel_measurement().await;
                let selected_only = args["selected"].as_bool().unwrap_or(false);
                let (profiles, settings, connected) = {
                    let i = self.inner.lock().await;
                    if matches!(i.core.status.as_str(), "connecting" | "disconnecting") {
                        return Err("Дождитесь завершения переключения VPN.".into());
                    }
                    let mut profiles = i.repo.state.profiles.clone();
                    if selected_only {
                        profiles.retain(|p| Some(p.key()) == i.repo.state.selected);
                    }
                    if let Some(keys) = args.get("keys") {
                        let keys = keys.as_array().ok_or("Некорректный список серверов.")?;
                        profiles.retain(|p| keys.contains(&json!(p.key())));
                    }
                    (
                        profiles,
                        i.repo.state.settings.clone(),
                        i.core.status == "connected",
                    )
                };
                let method = args["method"]
                    .as_str()
                    .unwrap_or(if selected_only {
                        &settings.latency_method
                    } else {
                        "tcp"
                    })
                    .to_string();
                if !["tcp", "icmp", "proxy"].contains(&method.as_str()) {
                    return Err("Неизвестный метод измерения.".into());
                }
                if self.host.android() && method == "proxy" && !selected_only {
                    return Err(
                        "На Android массовая проверка доступна через TCP/UDP и ICMP.".into(),
                    );
                }
                {
                    let mut i = self.inner.lock().await;
                    i.results.clear();
                    i.measure_total = profiles.len();
                }
                let e = self.clone();
                *self.measurement.lock().await = Some(tokio::spawn(async move {
                    stream::iter(profiles)
                        .map(|p| {
                            let e = e.clone();
                            let settings = settings.clone();
                            let method = method.clone();
                            async move {
                                let result = if method == "proxy" && !selected_only {
                                    e.host.probe(&p, &settings).await
                                } else {
                                    latency::measure(&p, &settings, &method, connected).await
                                };
                                e.inner.lock().await.results.insert(p.key(), result);
                            }
                        })
                        .buffer_unordered(8)
                        .collect::<Vec<_>>()
                        .await;
                }));
            }
            _ => return Err("Неизвестная команда интерфейса.".into()),
        }
        Ok(self.snapshot().await)
    }
    pub async fn shutdown(&self) -> Result<()> {
        if self.closed.swap(true, Ordering::SeqCst) {
            return Ok(());
        }
        if let Some(task) = self.scheduler.lock().await.take() {
            task.abort();
            let _ = task.await;
        }
        if let Some(task) = self.monitor.lock().await.take() {
            task.abort();
            let _ = task.await;
        }
        let _gate = self.gate.lock().await;
        self.cancel_measurement().await;
        if !self.host.android() {
            self.disconnect().await?;
        }
        Ok(())
    }
}

/// Tauri supplies only the platform operations required by Android.
pub type NativeCall = dyn Fn(&str, Value) -> Result<Value> + Send + Sync;
pub struct AndroidHost {
    pub call: Arc<NativeCall>,
}
#[async_trait]
impl Host for AndroidHost {
    fn android(&self) -> bool {
        true
    }
    async fn encrypt(&self, data: &[u8]) -> Result<Vec<u8>> {
        self.vault("vault_encrypt", data).await
    }
    async fn decrypt(&self, data: &[u8]) -> Result<Vec<u8>> {
        self.vault("vault_decrypt", data).await
    }
    async fn connect(&self, p: &Profile, s: &Settings) -> Result<CoreState> {
        let config = config::android(p, s, &secret(), &secret())?;
        let value=self.invoke("connect",json!({"config":config.to_string(),"probe_url":s.probe_url,"verify_connection":s.verify_connection,"server_name":p.name})).await?;
        serde_json::from_value(value)
            .map_err(|_| "Android VPN-служба вернула некорректное состояние.".into())
    }
    async fn disconnect(&self) -> Result<CoreState> {
        serde_json::from_value(self.invoke("disconnect", json!({})).await?)
            .map_err(|_| "Android не подтвердил отключение.".into())
    }
    async fn snapshot(&self) -> Result<CoreState> {
        serde_json::from_value(self.invoke("snapshot", json!({})).await?)
            .map_err(|_| "Android VPN-служба вернула некорректное состояние.".into())
    }
    async fn take_import_link(&self) -> Result<Value> {
        self.invoke("take_import_link", json!({})).await
    }
    async fn open_update_url(&self, url: &str) -> Result<()> {
        self.invoke("open_update_url", json!({"url":url})).await?;
        Ok(())
    }
}
impl AndroidHost {
    pub async fn invoke(&self, method: &str, args: Value) -> Result<Value> {
        let call = self.call.clone();
        let method = method.to_string();
        tokio::task::spawn_blocking(move || call(&method, args))
            .await
            .map_err(|_| "Android bridge stopped".to_string())?
    }
    async fn vault(&self, method: &str, data: &[u8]) -> Result<Vec<u8>> {
        let value = self
            .invoke(method, json!({"data":subscriptions::b64(data)}))
            .await?;
        parser::unbase64(value.as_str().ok_or("Android Keystore недоступен.")?)
    }
}
