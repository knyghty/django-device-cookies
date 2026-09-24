import datetime
from collections.abc import Callable
from collections.abc import Iterable
from unittest import mock

import pytest
from django.contrib.auth import _clean_credentials
from django.contrib.auth import get_user_model
from django.core.checks import CheckMessage
from django.core.checks import Error
from django.core.checks import Warning as CheckWarning
from django.core.checks import run_checks
from django.http import HttpRequest
from django.http import HttpResponseBase
from pytest_django.fixtures import Settings

from django_device_cookies import checks
from django_device_cookies import utils
from django_device_cookies.backends import DeviceCookieBackend

from .helpers import COMBINED
from .helpers import DJANGO
from .helpers import GATE

Summary = list[tuple[type[CheckMessage], str | None]]


class Subclass(DeviceCookieBackend):
    pass


def function_middleware(
    get_response: Callable[[HttpRequest], HttpResponseBase],
) -> Callable[[HttpRequest], HttpResponseBase]:
    return get_response


def summarize(messages: Iterable[CheckMessage]) -> Summary:
    return [(type(message), message.id) for message in messages]


def test_registered() -> None:
    messages = run_checks(tags=["security"], include_deployment_checks=True)
    assert [m for m in messages if m.id.startswith("device_cookies.")] == []


@pytest.mark.parametrize(
    ("backends", "expected"),
    [
        ([DJANGO], [(Error, "device_cookies.E001")]),
        ([DJANGO, GATE], [(CheckWarning, "device_cookies.W001")]),
        ([COMBINED], []),
        ([GATE], [(Error, "device_cookies.E005")]),
        (["tests.test_checks.Subclass", DJANGO], []),
        (["nonexistent.Backend", GATE], [(CheckWarning, "device_cookies.W001")]),
    ],
)
def test_backend(settings: Settings, backends: list[str], expected: Summary) -> None:
    settings.AUTHENTICATION_BACKENDS = backends
    assert summarize(checks.check_backend(None)) == expected


@pytest.mark.parametrize(
    "field", ["username", "email", "api_key", "token", "secret_id", "passphrase"]
)
def test_masked_pattern_matches_django(field: str) -> None:
    cleaned = _clean_credentials({field: "value"})
    masked = checks.is_masked(field)
    assert (cleaned[field] != "value") == masked
    assert (cleaned[field] == utils.MASK) == masked


def test_masked_username_field() -> None:
    with mock.patch.object(get_user_model(), "USERNAME_FIELD", "api_key"):
        assert summarize(checks.check_username_field(None)) == [
            (CheckWarning, "device_cookies.W003")
        ]


def test_middleware_missing(settings: Settings) -> None:
    settings.MIDDLEWARE = []
    assert summarize(checks.check_middleware(None)) == [(Error, "device_cookies.E002")]


def test_function_middleware_is_skipped(settings: Settings) -> None:
    settings.MIDDLEWARE = [
        "tests.test_checks.function_middleware",
        *settings.MIDDLEWARE,
    ]
    assert checks.check_middleware(None) == []


def test_secure_off_is_a_deployment_warning(settings: Settings) -> None:
    settings.DEVICE_COOKIE_SECURE = False
    assert summarize(checks.check_secure(None)) == [
        (CheckWarning, "device_cookies.W002")
    ]
    ids = [m.id for m in run_checks(include_deployment_checks=False)]
    assert "device_cookies.W002" not in ids


@pytest.mark.parametrize(
    ("name", "value"),
    [
        ("DEVICE_COOKIE_NAME", ""),
        ("DEVICE_COOKIE_NAME", "device cookie"),
        ("DEVICE_COOKIE_NAME", "path"),
        ("DEVICE_COOKIE_NAME", "Max-Age"),
        ("DEVICE_COOKIE_PATH", ""),
        ("DEVICE_COOKIE_PERIOD", 3600),
        ("DEVICE_COOKIE_PERIOD", datetime.timedelta(0)),
        ("DEVICE_COOKIE_ATTEMPTS_PER_PERIOD", 0),
        ("DEVICE_COOKIE_ATTEMPTS_PER_PERIOD", True),
        ("DEVICE_COOKIE_MAX_AGE", "1d"),
        ("DEVICE_COOKIE_SECURE", 1),
        ("DEVICE_COOKIE_PER_USER", "yes"),
        ("DEVICE_COOKIE_REVOKE_AFTER_FAILURES", 0),
        ("DEVICE_COOKIE_SAMESITE", "sometimes"),
        ("DEVICE_COOKIE_DOMAIN", 1),
    ],
)
def test_setting_types(settings: Settings, name: str, value: object) -> None:
    setattr(settings, name, value)
    (message,) = checks.check_settings(None)
    assert isinstance(message, Error)
    assert message.id == "device_cookies.E003"
    assert name in message.msg


def test_samesite_none_needs_secure(settings: Settings) -> None:
    settings.DEVICE_COOKIE_SAMESITE = "None"
    settings.DEVICE_COOKIE_SECURE = False
    assert summarize(checks.check_settings(None)) == [(Error, "device_cookies.E004")]
    settings.DEVICE_COOKIE_SECURE = True
    assert checks.check_settings(None) == []


def test_valid_alternative_settings(settings: Settings) -> None:
    settings.DEVICE_COOKIE_PERIOD = datetime.timedelta(minutes=5)
    settings.DEVICE_COOKIE_SAMESITE = None
    settings.DEVICE_COOKIE_DOMAIN = "example.com"
    settings.DEVICE_COOKIE_REVOKE_AFTER_FAILURES = 50
    assert checks.check_settings(None) == []
