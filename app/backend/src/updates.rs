//! Public GitHub Releases discovery. Downloads are handed to the OS browser.
use crate::Result;
use futures_util::StreamExt;
use serde::{Deserialize, Serialize};
use std::time::Duration;

pub const RELEASES_API: &str =
    "https://api.github.com/repos/GodPens656/Lunaris-VPN/releases/latest";
pub const DOWNLOAD_PREFIX: &str = "https://github.com/GodPens656/Lunaris-VPN/releases/download/";
const MAX_RELEASE_BYTES: usize = 1024 * 1024;

#[derive(Clone, Debug, Serialize)]
pub struct Update {
    pub version: String,
    pub current_version: String,
    pub asset_name: String,
    pub size: u64,
    // Only the backend may choose the URL used to start a download.
    #[serde(skip_serializing)]
    pub download_url: String,
}

#[derive(Clone, Copy, Debug)]
pub enum Platform {
    WindowsX64,
    AndroidArm64,
}
impl Platform {
    fn asset_name(self, version: &str) -> String {
        match self {
            Self::WindowsX64 => format!("LunarisClient-{version}-windows-x64.zip"),
            Self::AndroidArm64 => format!("LunarisClient-{version}-arm64.apk"),
        }
    }
}

#[derive(Deserialize)]
struct Release {
    tag_name: String,
    draft: bool,
    prerelease: bool,
    assets: Vec<Asset>,
}
#[derive(Deserialize)]
struct Asset {
    name: String,
    browser_download_url: String,
    size: u64,
    state: String,
}

// Stable release tags follow vMAJOR.MINOR.PATCH (the v prefix is optional).
fn version(value: &str) -> Option<([u64; 3], &str)> {
    let value = value.strip_prefix('v').unwrap_or(value);
    let parts: Vec<_> = value.split('.').collect();
    if parts.len() != 3 {
        return None;
    }
    let mut numbers = [0; 3];
    for (index, part) in parts.iter().enumerate() {
        if part.is_empty()
            || (part.len() > 1 && part.starts_with('0'))
            || !part.bytes().all(|c| c.is_ascii_digit())
        {
            return None;
        }
        numbers[index] = part.parse().ok()?;
    }
    Some((numbers, value))
}

pub fn validate_download_url(value: &str) -> Result<()> {
    let url = url::Url::parse(value).map_err(|_| "Некорректная ссылка обновления.")?;
    if value.len() > 8192
        || !value.starts_with(DOWNLOAD_PREFIX)
        || url.scheme() != "https"
        || url.host_str() != Some("github.com")
        || url.port().is_some()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || value.chars().any(|c| c.is_whitespace() || c.is_control())
        || url.path().split('/').count() != 7
        || url.path().split('/').skip(1).any(str::is_empty)
        || !url
            .path()
            .starts_with("/GodPens656/Lunaris-VPN/releases/download/")
    {
        return Err("Скачивание разрешено только из релизов Lunaris-VPN на GitHub.".into());
    }
    Ok(())
}

fn select_release(data: &[u8], current: &str, platform: Platform) -> Result<Option<Update>> {
    let release: Release =
        serde_json::from_slice(data).map_err(|_| "GitHub вернул некорректные данные релиза.")?;
    if release.draft || release.prerelease {
        return Ok(None);
    }
    let Some((latest, latest_text)) = version(&release.tag_name) else {
        return Ok(None);
    };
    let (installed, _) = version(current).ok_or("Не удалось определить версию приложения.")?;
    if latest <= installed {
        return Ok(None);
    }
    let expected = platform.asset_name(latest_text);
    let Some(asset) = release
        .assets
        .into_iter()
        .find(|a| a.name == expected && a.state == "uploaded" && a.size > 0)
    else {
        // A release may be published before both platform files are uploaded.
        return Ok(None);
    };
    validate_download_url(&asset.browser_download_url)?;
    let url = url::Url::parse(&asset.browser_download_url).unwrap();
    let expected_path = format!(
        "/GodPens656/Lunaris-VPN/releases/download/{}/{}",
        release.tag_name, expected
    );
    if url.path() != expected_path {
        return Err("Файл обновления не соответствует опубликованной версии.".into());
    }
    Ok(Some(Update {
        version: latest_text.into(),
        current_version: current.into(),
        asset_name: asset.name,
        size: asset.size,
        download_url: asset.browser_download_url,
    }))
}

async fn check_endpoint(
    endpoint: &str,
    current: &str,
    platform: Platform,
) -> Result<Option<Update>> {
    let client = reqwest::Client::builder()
        .no_proxy()
        .user_agent(format!("LunarisClient/{current}"))
        .connect_timeout(Duration::from_secs(5))
        .timeout(Duration::from_secs(12))
        .redirect(reqwest::redirect::Policy::limited(3))
        .build()
        .map_err(|_| "Не удалось начать проверку обновления.")?;
    let response = client
        .get(endpoint)
        .header("Accept", "application/vnd.github+json")
        .send()
        .await
        .map_err(|_| "Не удалось связаться с GitHub для проверки обновления.")?;
    if response.status() == reqwest::StatusCode::NOT_FOUND {
        return Ok(None);
    }
    if !response.status().is_success() {
        return Err("Проверка обновления временно недоступна на GitHub.".into());
    }
    let mut body = Vec::new();
    let mut stream = response.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|_| "Не удалось получить сведения об обновлении.")?;
        if body.len() + chunk.len() > MAX_RELEASE_BYTES {
            return Err("Ответ сервера обновления слишком большой.".into());
        }
        body.extend_from_slice(&chunk);
    }
    select_release(&body, current, platform)
}

pub async fn check(android: bool) -> Result<Option<Update>> {
    let platform = match (android, std::env::consts::ARCH) {
        (true, "aarch64") => Platform::AndroidArm64,
        (false, "x86_64") => Platform::WindowsX64,
        _ => return Ok(None),
    };
    check_endpoint(RELEASES_API, crate::VERSION, platform).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{json, Value};

    fn release(tag: &str) -> Value {
        let text = tag.strip_prefix('v').unwrap_or(tag);
        let assets: Vec<_> = [Platform::WindowsX64, Platform::AndroidArm64]
            .into_iter()
            .map(|platform| {
                let name = platform.asset_name(text);
                json!({"name":name,"size":4096,"state":"uploaded",
                    "browser_download_url":format!("{DOWNLOAD_PREFIX}{tag}/{name}")})
            })
            .collect();
        json!({"tag_name":tag,"draft":false,"prerelease":false,"assets":assets})
    }

    fn select(release: &Value, current: &str, platform: Platform) -> Result<Option<Update>> {
        select_release(&serde_json::to_vec(release).unwrap(), current, platform)
    }

    #[test]
    fn versions_are_compared_numerically_and_only_stable_newer_releases_are_offered() {
        for (tag, offered) in [
            ("v0.6.4", false),
            ("v0.6.5", false),
            ("0.6.6", true),
            ("v0.10.0", true),
            ("v1.0.0", true),
            ("v0.7.0-beta.1", false),
            ("v00.7.0", false),
            ("latest", false),
            ("v0.7", false),
        ] {
            assert_eq!(
                select(&release(tag), "0.6.5", Platform::WindowsX64)
                    .unwrap()
                    .is_some(),
                offered,
                "{tag}"
            );
        }
        for flag in ["draft", "prerelease"] {
            let mut data = release("v0.7.0");
            data[flag] = json!(true);
            assert!(select(&data, "0.6.5", Platform::WindowsX64)
                .unwrap()
                .is_none());
        }
    }

    #[test]
    fn platform_selection_never_uses_the_source_archive_or_the_other_platform() {
        let mut data = release("v0.7.0");
        for (platform, suffix) in [
            (Platform::WindowsX64, "windows-x64.zip"),
            (Platform::AndroidArm64, "arm64.apk"),
        ] {
            let update = select(&data, "0.6.5", platform).unwrap().unwrap();
            assert!(update.asset_name.ends_with(suffix));
            assert_eq!(update.version, "0.7.0");
            assert_eq!(update.current_version, "0.6.5");
            assert!(serde_json::to_value(&update)
                .unwrap()
                .get("download_url")
                .is_none());
        }
        data["assets"][0]["name"] = json!("LunarisClient-0.7.0-source.zip");
        assert!(select(&data, "0.6.5", Platform::WindowsX64)
            .unwrap()
            .is_none());
        assert!(select(&data, "0.6.5", Platform::AndroidArm64)
            .unwrap()
            .is_some());
        data["assets"][1]["state"] = json!("new");
        assert!(select(&data, "0.6.5", Platform::AndroidArm64)
            .unwrap()
            .is_none());
        data["assets"] = json!([]);
        assert!(select(&data, "0.6.5", Platform::WindowsX64)
            .unwrap()
            .is_none());
    }

    #[test]
    fn only_the_expected_release_asset_on_the_fixed_https_repository_is_accepted() {
        for url in [
            "https://example.com/update.zip",
            "http://github.com/GodPens656/Lunaris-VPN/releases/download/v0.7.0/file.zip",
            "https://github.com/other/repo/releases/download/v0.7.0/file.zip",
            "https://github.com.evil.test/GodPens656/Lunaris-VPN/releases/download/v0.7.0/file.zip",
            "https://github.com/GodPens656/Lunaris-VPN/releases/download//file.zip",
            "https://github.com/GodPens656/Lunaris-VPN/releases/download/v0.7.0/",
            "https://github.com/GodPens656/Lunaris-VPN/releases/download/v0.7.0/file.zip?redirect=1",
            "file:///C:/update.exe",
        ] {
            assert!(validate_download_url(url).is_err(), "{url}");
        }
        for path in [
            "v0.6.4/LunarisClient-0.7.0-windows-x64.zip",
            "v0.7.0/LunarisClient-0.7.0-source.zip",
        ] {
            let mut data = release("v0.7.0");
            data["assets"][0]["browser_download_url"] = json!(format!("{DOWNLOAD_PREFIX}{path}"));
            assert!(select(&data, "0.6.5", Platform::WindowsX64).is_err());
        }
    }

    #[tokio::test]
    async fn missing_releases_errors_and_bounded_responses_are_handled() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        for (status, body, success) in [
            (404, String::new(), true),
            (403, String::new(), false),
            (429, String::new(), false),
            (500, String::new(), false),
            (200, "invalid json".into(), false),
            (200, "x".repeat(MAX_RELEASE_BYTES + 1), false),
            (200, release("v0.7.0").to_string(), true),
        ] {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let endpoint = format!("http://{}/release", listener.local_addr().unwrap());
            let server = tokio::spawn(async move {
                let (mut socket, _) = listener.accept().await.unwrap();
                let mut request = [0; 4096];
                let n = socket.read(&mut request).await.unwrap();
                let request = String::from_utf8_lossy(&request[..n]).to_ascii_lowercase();
                assert!(request.contains("user-agent: lunarisclient/0.6.5"));
                assert!(request.contains("accept: application/vnd.github+json"));
                let response = format!(
                    "HTTP/1.1 {status} Test\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = socket.write_all(response.as_bytes()).await;
            });
            let result = check_endpoint(&endpoint, "0.6.5", Platform::WindowsX64).await;
            assert_eq!(result.is_ok(), success, "HTTP {status}");
            if status == 404 {
                assert!(result.unwrap().is_none());
            }
            server.await.unwrap();
        }
        assert!(
            check_endpoint("http://127.0.0.1:0/", "0.6.5", Platform::WindowsX64)
                .await
                .is_err()
        );
    }
}
