import re
from collections import deque
from datetime import datetime


class SafeLog:
    def __init__(self):
        self.lines = deque(maxlen=300)
        self.secrets: set[str] = set()

    def register(self, value):
        if isinstance(value, dict):
            for k, v in value.items():
                if k == "authentication" and isinstance(v, list):
                    for account in v:
                        if isinstance(account, str) and ":" in account:
                            password = account.split(":", 1)[1]
                            if password:
                                self.secrets.add(password)
                    continue
                if k == "encryption" and isinstance(v, str) and v and v != "none":
                    self.secrets.add(v)
                    self.secrets.update(part for part in v.split(".") if len(part) >= 32)
                elif k in {"uuid", "id", "password", "pass", "public_key", "publicKey", "public-key", "short_id", "shortId", "short-id", "obfs-password", "spiderX", "secret"} and isinstance(v, str) and v:
                    self.secrets.add(v)
                else:
                    self.register(v)
        elif isinstance(value, list):
            for v in value:
                self.register(v)

    def redact(self, text: str) -> str:
        text = re.sub(r"\x1b\[[0-9;]*m", "", text)
        for secret in sorted(self.secrets, key=len, reverse=True):
            text = text.replace(secret, "[скрыто]")
        text = re.sub(r"(?i)\b(?:https?|vless|trojan|hy2|hysteria2)://[^\s\"'<>]+", "[URL скрыт]", text)
        text = re.sub(r"(?i)\b[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}\b", "[UUID скрыт]", text)
        text = re.sub(r"(?i)(password|uuid|pbk|public_key|short_id|token|secret|authorization)\s*[:=]\s*[^\s,;]+", r"\1=[скрыто]", text)
        text = re.sub(r"\b[A-Za-z0-9_+/-]{32,}={0,2}\b", "[ключ скрыт]", text)
        return text[:1000]

    def add(self, text: str) -> None:
        self.lines.append(f"{datetime.now():%H:%M:%S}  {self.redact(text)}")
