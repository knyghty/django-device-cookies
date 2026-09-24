import hashlib
import secrets
import unicodedata
from collections.abc import Mapping

from django.contrib.auth import get_user_model
from django.contrib.auth.base_user import AbstractBaseUser
from django.core import signing
from django.core.exceptions import MultipleObjectsReturned
from django.core.exceptions import ObjectDoesNotExist
from django.core.exceptions import ValidationError
from django.http import HttpRequest
from django.http import HttpResponseBase
from django.views.decorators.debug import sensitive_variables

from . import config
from .models import FailedAuthenticationAttempt

SALT = "django_device_cookies"
META_KEY = "DEVICE_COOKIE_AUTH"
BUCKET_KEY = "DEVICE_COOKIE_AUTH_BUCKET"
MASK = "*" * 20


def normalize_username(username: object) -> str:
    normalized = unicodedata.normalize("NFKC", str(username)).casefold()
    return normalized[: config.USERNAME_MAX_LENGTH]


def get_username(credentials: Mapping[str, object]) -> str | None:
    username = credentials.get("username")
    if username is None:
        username = credentials.get(get_user_model().USERNAME_FIELD)
    if username is None or username == MASK:
        return None
    return str(username)


def find_user(username: str) -> AbstractBaseUser | None:
    try:
        return get_user_model()._default_manager.get_by_natural_key(username)
    except (ObjectDoesNotExist, MultipleObjectsReturned, ValidationError, ValueError):
        return None


def get_cookie_name(username: str) -> str:
    if not config.DEVICE_COOKIE_PER_USER:
        return config.DEVICE_COOKIE_NAME
    digest = hashlib.sha256(normalize_username(username).encode()).hexdigest()[:16]
    return f"{config.DEVICE_COOKIE_NAME}_{digest}"


def derive_nonce(secret: str) -> str:
    return hashlib.sha256(secret.encode()).hexdigest()[: config.NONCE_LENGTH]


def build_payload(user: AbstractBaseUser, nonce: str | None = None) -> dict[str, str]:
    return {
        "u": str(user.get_username()),
        "i": str(user.pk),
        "n": nonce or secrets.token_hex(config.NONCE_LENGTH // 2),
    }


def get_device(request: HttpRequest | None, user: AbstractBaseUser | None) -> str:
    if request is None or user is None:
        return ""
    cookie = request.COOKIES.get(get_cookie_name(user.get_username()), "")
    try:
        payload = signing.loads(cookie, salt=SALT, max_age=config.DEVICE_COOKIE_MAX_AGE)
    except signing.BadSignature:
        return ""
    owner = {"u": user.get_username(), "i": str(user.pk)}
    if not isinstance(payload, dict) or any(
        payload.get(k) != v for k, v in owner.items()
    ):
        return ""
    nonce = payload.get("n")
    if not isinstance(nonce, str) or len(nonce) != config.NONCE_LENGTH:
        return ""
    return nonce


@sensitive_variables()
def get_bucket(
    request: HttpRequest | None, credentials: Mapping[str, object]
) -> tuple[str, str] | None:
    username = get_username(credentials)
    if username is None:
        return None
    user = find_user(username)
    key = normalize_username(user.get_username() if user else username)
    device = get_device(request, user)
    if device and FailedAuthenticationAttempt.objects.is_revoked(key, device):
        device = ""
    return key, device


def stash_bucket(
    request: HttpRequest | None,
    credentials: Mapping[str, object],
    bucket: tuple[str, str] | None,
) -> None:
    if request is not None and bucket is not None:
        request.META[BUCKET_KEY] = (get_username(credentials), bucket)


@sensitive_variables()
def pop_bucket(
    request: HttpRequest | None, credentials: Mapping[str, object]
) -> tuple[str, str] | None:
    stash = request.META.pop(BUCKET_KEY, None) if request is not None else None
    if stash is not None and get_username(credentials) in (None, stash[0]):
        return stash[1]
    return get_bucket(request, credentials)


def trust_device(
    request: HttpRequest, user: AbstractBaseUser, nonce: str | None = None
) -> None:
    request.META[META_KEY] = build_payload(user, nonce)


def issue_device_cookie(response: HttpResponseBase, payload: dict[str, str]) -> None:
    response.set_cookie(
        get_cookie_name(payload["u"]),
        signing.dumps(payload, salt=SALT),
        max_age=config.DEVICE_COOKIE_MAX_AGE,
        path=config.DEVICE_COOKIE_PATH,
        domain=config.DEVICE_COOKIE_DOMAIN,
        secure=config.DEVICE_COOKIE_SECURE,
        httponly=True,
        samesite=config.DEVICE_COOKIE_SAMESITE,
    )
