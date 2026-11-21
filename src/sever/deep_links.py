"""Parse external import requests without fetching or exposing their credentials."""
from urllib.parse import unquote

from .models import UserError
from .subscriptions import validate_url


def subscription_url(link: str) -> str:
    error = "Некорректная ссылка импорта. Нужна lunaris://import://https://адрес-подписки."
    if not isinstance(link, str) or len(link) > 25000:
        raise UserError(error)
    # Browsers remove the empty port from the original `import:` authority.
    lower = link.lower()
    prefixes = ("lunaris://import://", "lunaris://import//")
    prefix = next((value for value in prefixes if lower.startswith(value)), None)
    if prefix is None:
        raise UserError(error)
    url = link[len(prefix):]
    # Decode a wrapped URL once, but preserve escapes in a normal subscription
    # URL: %2F, %26 and %2B may be part of its signed token.
    if not url.lower().startswith(("https://", "http://")):
        url = unquote(url)
    try:
        validate_url(url)
    except UserError:
        raise UserError(error) from None
    return url
