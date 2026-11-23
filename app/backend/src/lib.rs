//! Shared application backend. No Python interpreter or WebView credentials.
pub mod bootstrap;
pub mod config;
pub mod engine;
#[cfg(windows)]
mod flclash;
pub mod latency;
pub mod models;
pub mod parser;
pub mod redaction;
pub mod storage;
pub mod subscriptions;
pub mod updates;
#[cfg(windows)]
pub mod windows;

pub type Result<T> = std::result::Result<T, String>;
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
pub const SING_BOX: &str = "1.14.4";
pub const XRAY: &str = "26.11.9";
pub const MIHOMO: &str = "1.19.34";
