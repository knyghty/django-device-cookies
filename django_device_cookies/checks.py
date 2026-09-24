import datetime
import inspect
from collections.abc import Callable
from collections.abc import Iterable
from collections.abc import Sequence
from http.cookies import CookieError
from http.cookies import SimpleCookie

from django.apps import AppConfig
from django.conf import settings
from django.contrib.auth import get_user_model
from django.core import checks
from django.utils.module_loading import import_string

from . import config
from .backends import DeviceCookieBackend
from .backends import DeviceCookieModelBackend
from .middleware import DeviceCookieMiddleware


def load_class(path: str) -> type | None:
    try:
        obj = import_string(path)
    except ImportError:
        return None
    return obj if inspect.isclass(obj) else None


def find_first(paths: Iterable[str], classes: type | tuple[type, ...]) -> int | None:
    for index, path in enumerate(paths):
        cls = load_class(path)
        if cls is not None and issubclass(cls, classes):
            return index
    return None


def is_gate(path: str) -> bool:
    cls = load_class(path)
    return cls is not None and issubclass(cls, DeviceCookieBackend)


@checks.register(checks.Tags.security)
def check_backend(
    app_configs: Sequence[AppConfig] | None, **kwargs: object
) -> list[checks.CheckMessage]:
    backends = (DeviceCookieBackend, DeviceCookieModelBackend)
    index = find_first(settings.AUTHENTICATION_BACKENDS, backends)
    if index is None:
        return [
            checks.Error(
                "AUTHENTICATION_BACKENDS has no device cookie backend. Nothing "
                "throttles logins.",
                hint='Add "django_device_cookies.backends.DeviceCookieBackend" as '
                "the first entry.",
                id="device_cookies.E001",
            )
        ]
    if index:
        return [
            checks.Warning(
                "The device cookie backend is not first in AUTHENTICATION_BACKENDS. "
                "A locked-out client that knows the password still logs in.",
                hint="Move it to the first entry.",
                id="device_cookies.W001",
            )
        ]
    if all(is_gate(path) for path in settings.AUTHENTICATION_BACKENDS):
        return [
            checks.Error(
                "AUTHENTICATION_BACKENDS has only the device cookie backend. Nothing "
                "authenticates.",
                hint='Add "django.contrib.auth.backends.ModelBackend" after it.',
                id="device_cookies.E005",
            )
        ]
    return []


@checks.register(checks.Tags.security)
def check_middleware(
    app_configs: Sequence[AppConfig] | None, **kwargs: object
) -> list[checks.CheckMessage]:
    if find_first(settings.MIDDLEWARE, DeviceCookieMiddleware) is not None:
        return []
    return [
        checks.Error(
            "MIDDLEWARE has no device cookie middleware. No client gets a device "
            "cookie, and every login attempt counts as untrusted.",
            hint='Add "django_device_cookies.middleware.DeviceCookieMiddleware".',
            id="device_cookies.E002",
        )
    ]


MASKED_WORDS = ("api", "token", "key", "secret", "password", "signature")


def is_masked(field: str) -> bool:
    return any(word in field.lower() for word in MASKED_WORDS)


@checks.register(checks.Tags.security)
def check_username_field(
    app_configs: Sequence[AppConfig] | None, **kwargs: object
) -> list[checks.CheckMessage]:
    field = get_user_model().USERNAME_FIELD
    if not is_masked(field):
        return []
    return [
        checks.Warning(
            f"Django masks USERNAME_FIELD {field!r} in the user_login_failed signal. "
            "The throttle ignores calls to authenticate() without a request that "
            "pass it by name.",
            hint="Pass the request to authenticate(), or give the field a name "
            "without api, token, key, secret, password or signature.",
            id="device_cookies.W003",
        )
    ]


@checks.register(checks.Tags.security, deploy=True)
def check_secure(
    app_configs: Sequence[AppConfig] | None, **kwargs: object
) -> list[checks.CheckMessage]:
    if config.DEVICE_COOKIE_SECURE:
        return []
    return [
        checks.Warning(
            "DEVICE_COOKIE_SECURE is off. Browsers send device cookies over HTTP.",
            hint="Set DEVICE_COOKIE_SECURE = True.",
            id="device_cookies.W002",
        )
    ]


def is_positive(delta: object) -> bool:
    return isinstance(delta, datetime.timedelta) and delta > datetime.timedelta(0)


def is_nonempty_str(value: object) -> bool:
    return isinstance(value, str) and value != ""


def is_cookie_name(value: object) -> bool:
    if not isinstance(value, str):
        return False
    try:
        SimpleCookie()[value] = ""
    except CookieError:
        return False
    return True


def is_positive_int(value: object) -> bool:
    return type(value) is int and value >= 1


def is_bool(value: object) -> bool:
    return isinstance(value, bool)


def is_samesite(value: object) -> bool:
    return not value or (
        isinstance(value, str) and value.lower() in {"lax", "none", "strict"}
    )


RULES: list[tuple[str, Callable[[object], bool], str]] = [
    ("DEVICE_COOKIE_NAME", is_cookie_name, "a valid cookie name"),
    ("DEVICE_COOKIE_PATH", is_nonempty_str, "a non-empty string"),
    ("DEVICE_COOKIE_PERIOD", is_positive, "a positive timedelta"),
    ("DEVICE_COOKIE_ATTEMPTS_PER_PERIOD", is_positive_int, "a positive integer"),
    ("DEVICE_COOKIE_MAX_AGE", is_positive, "a positive timedelta"),
    ("DEVICE_COOKIE_SECURE", is_bool, "a boolean"),
    ("DEVICE_COOKIE_PER_USER", is_bool, "a boolean"),
    (
        "DEVICE_COOKIE_REVOKE_AFTER_FAILURES",
        lambda v: v is None or is_positive_int(v),
        "None or a positive integer",
    ),
    ("DEVICE_COOKIE_SAMESITE", is_samesite, '"Lax", "Strict", "None" or false'),
    (
        "DEVICE_COOKIE_DOMAIN",
        lambda v: v is None or isinstance(v, str),
        "None or a string",
    ),
]


@checks.register(checks.Tags.security)
def check_settings(
    app_configs: Sequence[AppConfig] | None, **kwargs: object
) -> list[checks.CheckMessage]:
    errors: list[checks.CheckMessage] = [
        checks.Error(f"{name} must be {expected}.", id="device_cookies.E003")
        for name, ok, expected in RULES
        if not ok(getattr(config, name))
    ]
    samesite = config.DEVICE_COOKIE_SAMESITE
    cross_site = isinstance(samesite, str) and samesite.lower() == "none"
    if cross_site and not config.DEVICE_COOKIE_SECURE:
        errors.append(
            checks.Error(
                "Browsers reject a SameSite=None cookie that is not Secure. "
                "No client gets a device cookie.",
                hint="Set DEVICE_COOKIE_SECURE = True.",
                id="device_cookies.E004",
            )
        )
    return errors
