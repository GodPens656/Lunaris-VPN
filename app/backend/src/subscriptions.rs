use crate::{
    models::{Profile, State},
    parser::{self, MAX_BODY},
    Result,
};
use base64::Engine;
use futures_util::StreamExt;
use serde_json::{json, Value};
use std::time::Duration;

pub fn validate_url(value: &str) -> Result<url::Url> {
    let u = url::Url::parse(value)
        .map_err(|_| "Нужен корректный HTTP/HTTPS URL без userinfo и фрагмента.")?;
    if value.len() > 8192
        || value.chars().any(|c| c.is_whitespace() || c.is_control())
        || !matches!(u.scheme(), "http" | "https")
        || u.host_str().is_none()
        || !u.username().is_empty()
        || u.password().is_some()
        || u.fragment().is_some()
        || u.port() == Some(0)
    {
        return Err("Нужен корректный HTTP/HTTPS URL без userinfo и фрагмента.".into());
    }
    Ok(u)
}
pub fn subscription_url(link: &str) -> Result<String> {
    let error = "Некорректная ссылка импорта. Нужна lunaris://import://https://адрес-подписки.";
    if link.len() > 25000 {
        return Err(error.into());
    }
    // Browsers parse `import:` as a host with an empty port and remove its colon.
    let prefix = ["lunaris://import://", "lunaris://import//"]
        .into_iter()
        .find(|prefix| {
            link.get(..prefix.len())
                .is_some_and(|value| value.eq_ignore_ascii_case(prefix))
        })
        .ok_or(error)?;
    let value = &link[prefix.len()..];
    let value = if value.to_lowercase().starts_with("http://")
        || value.to_lowercase().starts_with("https://")
    {
        value.into()
    } else {
        parser::decode(value)?
    };
    validate_url(&value).map_err(|_| error)?;
    Ok(value)
}
pub fn title(value: Option<&str>) -> Option<String> {
    let v = value?.trim();
    if v.len() > 2048 {
        return None;
    }
    let decoded = if v
        .get(..7)
        .is_some_and(|s| s.eq_ignore_ascii_case("base64:"))
    {
        String::from_utf8(parser::unbase64(v[7..].trim()).ok()?).ok()?
    } else {
        v.into()
    };
    let s = decoded
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect::<String>()
        .trim()
        .chars()
        .take(100)
        .collect::<String>();
    (!s.is_empty()).then_some(s)
}
pub fn userinfo(value: Option<&str>) -> Value {
    let mut result = json!({});
    if let Some(s) = value.filter(|s| s.len() <= 2048) {
        for item in s.split(';') {
            if let Some((k, v)) = item.split_once('=') {
                let k = k.trim();
                let v = v.trim();
                if ["upload", "download", "total", "expire"].contains(&k)
                    && v.len() <= 20
                    && v.bytes().all(|c| c.is_ascii_digit())
                {
                    if let Ok(n) = v.parse::<u64>() {
                        result[k] = json!(n);
                    }
                }
            }
        }
    }
    result
}
pub fn description(value: Option<&str>) -> Option<String> {
    let value = value?.trim();
    if value.len() > 16384 {
        return None;
    }
    let decoded = if value
        .get(..7)
        .is_some_and(|s| s.eq_ignore_ascii_case("base64:"))
    {
        String::from_utf8(parser::unbase64(value[7..].trim()).ok()?).ok()?
    } else {
        value.into()
    };
    let text = decoded
        .replace("\r\n", "\n")
        .chars()
        .filter(|c| !c.is_control() || matches!(c, '\n' | '\t'))
        .take(4000)
        .collect::<String>()
        .trim()
        .to_string();
    (!text.is_empty()).then_some(text)
}

fn body_description(body: &[u8]) -> Option<String> {
    let text = std::str::from_utf8(body)
        .ok()?
        .trim_start_matches('\u{feff}')
        .trim();
    let decoded;
    let text = if !text.contains("://") && !text.contains("\\://") {
        let compact = text
            .chars()
            .filter(|c| !c.is_whitespace())
            .collect::<String>();
        decoded = String::from_utf8(parser::unbase64(&compact).ok()?).ok()?;
        decoded.as_str()
    } else {
        text
    };
    text.trim_start_matches('\u{feff}')
        .lines()
        .find_map(|line| {
            let (key, value) = line.trim().strip_prefix('#')?.split_once(':')?;
            key.trim()
                .eq_ignore_ascii_case("announce")
                .then(|| description(Some(value)))
                .flatten()
        })
}

pub struct FetchedSubscription {
    pub body: Vec<u8>,
    pub userinfo: Value,
    pub title: Option<String>,
    pub description: Option<String>,
}

pub async fn fetch(value: &str) -> Result<FetchedSubscription> {
    let mut url = validate_url(value)?;
    let original_https = url.scheme() == "https";
    let client = reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(20))
        .user_agent(format!("LunarisVPN/{}", crate::VERSION))
        .build()
        .map_err(|_| "Не удалось создать HTTPS-клиент.")?;
    let operation = async {
        for redirect in 0..=3 {
            let response = client
                .get(url.clone())
                .header("Accept", "text/plain")
                .header("Accept-Encoding", "identity")
                .send()
                .await
                .map_err(|_| {
                    "Не удалось загрузить подписку. Проверьте сеть, URL и TLS-сертификат."
                })?;
            if matches!(response.status().as_u16(), 301 | 302 | 303 | 307 | 308) {
                if redirect == 3 {
                    return Err("Слишком много перенаправлений (максимум 3).".into());
                }
                let location = response
                    .headers()
                    .get("location")
                    .and_then(|v| v.to_str().ok())
                    .ok_or("Сервер вернул перенаправление без адреса.")?;
                url = url
                    .join(location)
                    .map_err(|_| "Некорректное перенаправление.")?;
                validate_url(url.as_str())?;
                if original_https && url.scheme() != "https" {
                    return Err(
                        "Подписка перенаправляет HTTPS на HTTP. Обновление отменено.".into(),
                    );
                }
                continue;
            }
            if !response.status().is_success() {
                return Err(format!(
                    "HTTP {}. Предыдущие серверы сохранены.",
                    response.status().as_u16()
                ));
            }
            if response
                .headers()
                .get("content-type")
                .and_then(|v| v.to_str().ok())
                .is_some_and(|s| s.to_lowercase().contains("html"))
            {
                return Err("Вместо подписки получена HTML-страница.".into());
            }
            if response
                .content_length()
                .is_some_and(|n| n > MAX_BODY as u64)
            {
                return Err("Подписка превышает лимит 2 МиБ.".into());
            }
            let info = userinfo(
                response
                    .headers()
                    .get("subscription-userinfo")
                    .and_then(|v| v.to_str().ok()),
            );
            let name = title(
                response
                    .headers()
                    .get("profile-title")
                    .and_then(|v| v.to_str().ok()),
            );
            let description = description(
                response
                    .headers()
                    .get("announce")
                    .and_then(|v| std::str::from_utf8(v.as_bytes()).ok()),
            );
            let mut stream = response.bytes_stream();
            let mut body = Vec::new();
            while let Some(chunk) = stream.next().await {
                let chunk = chunk.map_err(|_| "Не удалось прочитать подписку.")?;
                if body.len() + chunk.len() > MAX_BODY {
                    return Err("Подписка превышает лимит 2 МиБ.".into());
                }
                body.extend_from_slice(&chunk);
            }
            let description = description.or_else(|| body_description(&body));
            return Ok(FetchedSubscription {
                body,
                userinfo: info,
                title: name,
                description,
            });
        }
        Err("Не удалось получить подписку.".into())
    };
    tokio::time::timeout(Duration::from_secs(20), operation)
        .await
        .map_err(|_| "Истекло время запроса подписки (20 секунд).")?
}
pub fn replacement(
    selected: &Profile,
    previous: &[Profile],
    updated: &[Profile],
) -> Option<String> {
    fn signature(p: &Profile, level: u8) -> String {
        let endpoint = json!([
            p.protocol(),
            p.outbound["server"].as_str().unwrap_or("").to_lowercase(),
            p.outbound["server_port"]
        ]);
        let name = json!([p.protocol(), p.name.trim()]);
        match level {
            0 => json!([name, endpoint]).to_string(),
            1 => endpoint.to_string(),
            _ => name.to_string(),
        }
    }
    for level in 0..3 {
        let id = signature(selected, level);
        if previous
            .iter()
            .filter(|p| signature(p, level) == id)
            .count()
            != 1
        {
            continue;
        }
        let candidates: Vec<_> = updated
            .iter()
            .filter(|p| signature(p, level) == id)
            .collect();
        if candidates.len() == 1 {
            return Some(candidates[0].key());
        }
    }
    None
}
pub fn replace_profiles(state: &mut State, id: &str, profiles: Vec<Profile>) {
    let previous: Vec<_> = state
        .profiles
        .iter()
        .filter(|p| p.source_id.as_deref() == Some(id))
        .cloned()
        .collect();
    let selected = previous
        .iter()
        .find(|p| Some(p.key()) == state.selected)
        .cloned();
    let alternative = selected.and_then(|p| replacement(&p, &previous, &profiles));
    state
        .profiles
        .retain(|p| p.source_id.as_deref() != Some(id));
    state.profiles.extend(profiles);
    if !state
        .profiles
        .iter()
        .any(|p| Some(p.key()) == state.selected)
    {
        state.selected = alternative.or_else(|| state.profiles.first().map(Profile::key));
    }
}
pub fn b64(data: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(data)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn announcements_decode_utf8_preserve_lines_and_bound_untrusted_text() {
        let text = "Описание подписки\nНовости от создателя 🌙";
        assert_eq!(description(Some(text)).as_deref(), Some(text));
        assert_eq!(
            description(Some(&format!("BASE64:{}", b64(text.as_bytes())))).as_deref(),
            Some(text)
        );
        assert_eq!(
            description(Some(" text\r\nsecond\0\u{7f} ")).as_deref(),
            Some("text\nsecond")
        );
        for value in [None, Some("  "), Some("base64:%%%"), Some("base64:/w==")] {
            assert_eq!(description(value), None);
        }
        assert_eq!(
            description(Some(&"я".repeat(5000)))
                .unwrap()
                .chars()
                .count(),
            4000
        );
        assert_eq!(description(Some(&"x".repeat(16385))), None);
    }

    #[test]
    fn announcements_support_plain_and_base64_subscription_comments() {
        let body = format!(
            "\u{feff}#other: ignored\n#Announce: base64:{}\ntrojan://secret@example.com",
            b64("Текст\nВторая строка".as_bytes())
        );
        assert_eq!(
            body_description(body.as_bytes()).as_deref(),
            Some("Текст\nВторая строка")
        );
        assert_eq!(
            body_description(b64(body.as_bytes()).as_bytes()).as_deref(),
            Some("Текст\nВторая строка")
        );
        assert_eq!(
            body_description(b"#announce: Plain announcement\ntrojan://secret@example.com")
                .as_deref(),
            Some("Plain announcement")
        );
        assert_eq!(
            body_description(b"trojan://secret@example.com#announce: ignored"),
            None
        );
    }
}
