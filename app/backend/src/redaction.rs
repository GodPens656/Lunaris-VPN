use regex::Regex;
use serde_json::Value;
use std::collections::{BTreeSet, VecDeque};

#[derive(Default)]
pub struct SafeLog {
    pub lines: VecDeque<String>,
    secrets: BTreeSet<String>,
}
impl SafeLog {
    pub fn register(&mut self, value: &Value) {
        match value {
            Value::Object(map) => {
                for (k, v) in map {
                    if matches!(
                        k.as_str(),
                        "uuid"
                            | "id"
                            | "password"
                            | "pass"
                            | "public_key"
                            | "publicKey"
                            | "public-key"
                            | "short_id"
                            | "shortId"
                            | "short-id"
                            | "obfs-password"
                            | "spiderX"
                            | "secret"
                            | "encryption"
                    ) {
                        if let Some(s) = v.as_str().filter(|s| !s.is_empty() && *s != "none") {
                            self.secrets.insert(s.to_string());
                        }
                    } else if k == "authentication" {
                        if let Some(a) = v.as_array() {
                            for s in a.iter().filter_map(Value::as_str) {
                                if let Some((_, p)) = s.split_once(':') {
                                    if !p.is_empty() {
                                        self.secrets.insert(p.into());
                                    }
                                }
                            }
                        }
                    } else {
                        self.register(v);
                    }
                }
            }
            Value::Array(a) => {
                for v in a {
                    self.register(v);
                }
            }
            _ => {}
        }
    }
    pub fn redact(&self, input: &str) -> String {
        let mut text = Regex::new(r"\x1b\[[0-9;]*m")
            .unwrap()
            .replace_all(input, "")
            .into_owned();
        let mut secrets: Vec<_> = self.secrets.iter().collect();
        secrets.sort_by_key(|s| std::cmp::Reverse(s.len()));
        for secret in secrets {
            text = text.replace(secret, "[скрыто]");
        }
        for (pattern, replacement) in [
            (
                r#"(?i)\b(?:https?|vless|trojan|hy2|hysteria2)://[^\s\"'<>]+"#,
                "[URL скрыт]",
            ),
            (
                r"(?i)\b[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}\b",
                "[UUID скрыт]",
            ),
            (
                r"(?i)(password|uuid|pbk|public_key|short_id|token|secret|authorization)\s*[:=]\s*[^\s,;]+",
                "${1}=[скрыто]",
            ),
            (r"\b[A-Za-z0-9_+/-]{32,}={0,2}\b", "[ключ скрыт]"),
        ] {
            text = Regex::new(pattern)
                .unwrap()
                .replace_all(&text, replacement)
                .into_owned();
        }
        text.chars().take(1000).collect()
    }
    pub fn add(&mut self, text: &str) {
        if self.lines.len() == 300 {
            self.lines.pop_front();
        }
        self.lines.push_back(self.redact(text));
    }
}
