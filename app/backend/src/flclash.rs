//! Desktop transport for the FlClash v0.9.4 core.

use crate::{engine::Log, Result};
use serde_json::{json, Value};
use std::{os::windows::io::AsRawHandle, path::Path, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::windows::named_pipe::NamedPipeServer,
    time::timeout,
};
use windows_sys::Win32::System::Pipes::GetNamedPipeClientProcessId;

const MAX_FRAME: u32 = 64 * 1024 * 1024;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(15);

pub(crate) struct Core {
    pipe: NamedPipeServer,
    log: Log,
}

impl Core {
    pub(crate) async fn accept(pipe: NamedPipeServer, pid: u32, log: Log) -> Result<Self> {
        timeout(Duration::from_secs(10), pipe.connect())
            .await
            .map_err(|_| "FlClashCore не подключился к именованному каналу.")?
            .map_err(|_| "Не удалось принять соединение FlClashCore.")?;
        let mut peer = 0;
        let identity = unsafe { GetNamedPipeClientProcessId(pipe.as_raw_handle(), &mut peer) };
        if identity == 0 || peer != pid {
            return Err("К именованному каналу подключился неизвестный процесс.".into());
        }
        Ok(Self { pipe, log })
    }

    pub(crate) async fn start(&mut self, home: &Path, test_url: &str) -> Result<()> {
        self.request("core.init", json!({"home-dir": home, "version": 0}))
            .await?;
        self.request(
            "config.setup",
            json!({"selected-map": {}, "options": {"test-url": test_url}}),
        )
        .await?;
        self.request("listener.start", Value::Null).await?;
        Ok(())
    }

    pub(crate) async fn stop(&mut self) {
        let _ = timeout(
            Duration::from_secs(2),
            self.request("listener.stop", Value::Null),
        )
        .await;
    }

    pub(crate) async fn check(&mut self, url: &str) -> Result<()> {
        let result = self
            .request(
                "proxy.testDelay",
                json!({"proxy-name": "proxy", "test-url": url, "timeout": 10000}),
            )
            .await?;
        if result["value"].as_u64().is_none_or(|delay| delay == 0) {
            return Err("Сервер не прошёл проверку HTTPS через ядро.".into());
        }
        Ok(())
    }

    pub(crate) async fn traffic(&mut self) -> Result<(u64, u64)> {
        #[derive(serde::Deserialize)]
        struct Traffic {
            up: u64,
            down: u64,
        }
        let traffic: Traffic = serde_json::from_value(
            self.request("traffic.total", json!({"only-proxy": false}))
                .await?,
        )
        .map_err(|_| "Некорректная статистика FlClashCore.")?;
        Ok((traffic.up, traffic.down))
    }

    async fn request(&mut self, method: &str, arguments: Value) -> Result<Value> {
        let id = uuid::Uuid::new_v4().to_string();
        let frame = json!({"id": id, "method": method, "arguments": arguments}).to_string();
        let response = timeout(REQUEST_TIMEOUT, async {
            self.pipe.write_u32_le(frame.len() as u32).await?;
            self.pipe.write_all(frame.as_bytes()).await?;
            loop {
                let len = self.pipe.read_u32_le().await?;
                if len == 0 || len > MAX_FRAME {
                    return Err(std::io::Error::other("invalid FlClash frame length"));
                }
                let mut buffer = vec![0; len as usize];
                self.pipe.read_exact(&mut buffer).await?;
                let reply: Value = serde_json::from_slice(&buffer)?;
                if reply["id"] == id {
                    return Ok(reply);
                }
            }
        })
        .await
        .map_err(|_| format!("FlClashCore не ответил на {method}."))?
        .map_err(|_| "Потеряна связь с FlClashCore.")?;
        if !response["error"].is_null() {
            if let Some(message) = response["error"]["message"].as_str() {
                self.log
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .add(message);
            }
            return Err(format!(
                "FlClashCore отклонил {method}. Подробности доступны в журнале."
            ));
        }
        response
            .get("result")
            .cloned()
            .ok_or_else(|| "Некорректный ответ FlClashCore.".into())
    }
}
