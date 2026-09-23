"""Read package settings at use time so ``override_settings`` applies."""

import datetime

from django.conf import settings

NONCE_LENGTH = 32
USERNAME_MAX_LENGTH = 255

DEVICE_COOKIE_NAME: str
DEVICE_COOKIE_PERIOD: datetime.timedelta
DEVICE_COOKIE_ATTEMPTS_PER_PERIOD: int
DEVICE_COOKIE_MAX_AGE: datetime.timedelta
DEVICE_COOKIE_SECURE: bool
DEVICE_COOKIE_SAMESITE: str | None
DEVICE_COOKIE_DOMAIN: str | None
DEVICE_COOKIE_PATH: str
DEVICE_COOKIE_PER_USER: bool
DEVICE_COOKIE_REVOKE_AFTER_FAILURES: int | None

DEFAULTS = {
    "DEVICE_COOKIE_NAME": "django_device",
    "DEVICE_COOKIE_PERIOD": datetime.timedelta(minutes=15),
    "DEVICE_COOKIE_ATTEMPTS_PER_PERIOD": 5,
    "DEVICE_COOKIE_MAX_AGE": datetime.timedelta(days=365),
    "DEVICE_COOKIE_SECURE": True,
    "DEVICE_COOKIE_SAMESITE": "Lax",
    "DEVICE_COOKIE_DOMAIN": None,
    "DEVICE_COOKIE_PATH": "/",
    "DEVICE_COOKIE_PER_USER": False,
    "DEVICE_COOKIE_REVOKE_AFTER_FAILURES": None,
}


def __getattr__(name: str) -> object:
    if name not in DEFAULTS:
        raise AttributeError(name)
    return getattr(settings, name, DEFAULTS[name])
