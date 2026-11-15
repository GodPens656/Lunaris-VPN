//! Shared application backend. No Python interpreter or WebView credentials.
pub mod bootstrap;
pub mod config;
pub mod engine;
pub mod latency;
pub mod models;
pub mod parser;
pub mod redaction;
pub mod storage;
pub mod subscriptions;
#[cfg(windows)]
pub mod windows;

pub type Result<T> = std::result::Result<T, String>;
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
pub const SING_BOX: &str = "1.14.0";
pub const XRAY: &str = "26.3.27";
pub const MIHOMO: &str = "1.19.32";
