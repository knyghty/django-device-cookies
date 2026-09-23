import hashlib
import secrets
import unicodedata
from collections.abc import Mapping

from django.contrib.auth import get_user_model
from django.core import signing
from django.core.exceptions import MultipleObjectsReturned
from django.core.exceptions import ObjectDoesNotExist
from django.core.exceptions import ValidationError
from django.http import HttpRequest
from django.http import HttpResponseBase

from . import config
from .models import FailedAuthenticationAttempt

SALT = "django_device_cookies"
META_KEY = "DEVICE_COOKIE_USERNAME"
MASK = "*" * 20


def normalize_username(username: object) -> str:
    normalized = unicodedata.normalize("NFKC", str(username)).casefold()
    return normalized[: config.USERNAME_MAX_LENGTH]


def get_username(credentials: Mapping[str, object]) -> str | None:
    """Return None for a value that Django masked in ``user_login_failed``."""
    username = credentials.get("username")
    if username is None:
        username = credentials.get(get_user_model().USERNAME_FIELD)
    if username is None or username == MASK:
        return None
    return str(username)


def get_canonical_username(username: str) -> str | None:
    try:
        user = get_user_model()._default_manager.get_by_natural_key(username)
    except (ObjectDoesNotExist, MultipleObjectsReturned, ValidationError, ValueError):
        return None
    return str(user.get_username())


def get_cookie_name(username: str) -> str:
    if not config.DEVICE_COOKIE_PER_USER:
        return config.DEVICE_COOKIE_NAME
    digest = hashlib.sha256(normalize_username(username).encode()).hexdigest()[:16]
    return f"{config.DEVICE_COOKIE_NAME}_{digest}"


def derive_nonce(secret: str) -> str:
    return hashlib.sha256(secret.encode()).hexdigest()[: config.NONCE_LENGTH]


def get_device(
    request: HttpRequest | None, username: str, canonical: str | None = None
) -> str:
    owner = canonical or username
    cookie = request.COOKIES.get(get_cookie_name(owner)) if request else None
    if not cookie:
        return ""
    try:
        payload = signing.loads(cookie, salt=SALT, max_age=config.DEVICE_COOKIE_MAX_AGE)
    except signing.BadSignature:
        return ""
    if not isinstance(payload, dict) or payload.get("u") not in (username, owner):
        return ""
    nonce = payload.get("n")
    if not isinstance(nonce, str) or len(nonce) != config.NONCE_LENGTH:
        return ""
    return nonce


def get_bucket(
    request: HttpRequest | None, credentials: Mapping[str, object]
) -> tuple[str, str] | None:
    """Key the bucket by the account, so spellings the database equates share it."""
    username = get_username(credentials)
    if username is None:
        return None
    canonical = get_canonical_username(username)
    key = normalize_username(canonical or username)
    device = get_device(request, username, canonical)
    if device and FailedAuthenticationAttempt.objects.is_revoked(key, device):
        device = ""
    return key, device


def trust_device(request: HttpRequest, username: str, nonce: str | None = None) -> None:
    """Use ``META``, not an attribute: REST framework's request proxies reads only."""
    request.META[META_KEY] = (username, nonce)


def issue_device_cookie(
    response: HttpResponseBase, username: str, nonce: str | None = None
) -> None:
    username = str(username)
    nonce = nonce or secrets.token_hex(config.NONCE_LENGTH // 2)
    response.set_cookie(
        get_cookie_name(username),
        signing.dumps({"u": username, "n": nonce}, salt=SALT),
        max_age=config.DEVICE_COOKIE_MAX_AGE,
        path=config.DEVICE_COOKIE_PATH,
        domain=config.DEVICE_COOKIE_DOMAIN,
        secure=config.DEVICE_COOKIE_SECURE,
        httponly=True,
        samesite=config.DEVICE_COOKIE_SAMESITE,
    )
