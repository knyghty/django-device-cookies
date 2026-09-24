import datetime

import pytest
from django.contrib.auth.models import User
from django.test import Client
from pytest_django.fixtures import Settings

from django_device_cookies import config
from django_device_cookies.models import FailedAuthenticationAttempt

from .helpers import COOKIE
from .helpers import age
from .helpers import fail
from .helpers import logged_in
from .helpers import login

pytestmark = pytest.mark.django_db


def test_unknown_setting() -> None:
    with pytest.raises(AttributeError):
        _ = config.DEVICE_COOKIE_FLAVOUR


def test_name(client: Client, user: User, settings: Settings) -> None:
    settings.DEVICE_COOKIE_NAME = "trusted"
    cookies = login(client).cookies
    assert "trusted" in cookies
    assert COOKIE not in cookies


def test_attempts_per_period(client: Client, user: User, settings: Settings) -> None:
    settings.DEVICE_COOKIE_ATTEMPTS_PER_PERIOD = 1
    fail(client, 1)
    assert not logged_in(login(client))


def test_period(client: Client, user: User, settings: Settings) -> None:
    settings.DEVICE_COOKIE_PERIOD = datetime.timedelta(minutes=1)
    fail(client)
    assert not logged_in(login(client))
    age(FailedAuthenticationAttempt.objects.all(), datetime.timedelta(minutes=2))
    assert logged_in(login(client))


def test_max_age(client: Client, user: User, settings: Settings) -> None:
    settings.DEVICE_COOKIE_MAX_AGE = datetime.timedelta(days=1)
    assert login(client).cookies[COOKIE]["max-age"] == 24 * 60 * 60


def test_cookie_attributes(client: Client, user: User, settings: Settings) -> None:
    settings.DEVICE_COOKIE_DOMAIN = "example.com"
    settings.DEVICE_COOKIE_PATH = "/app/"
    settings.DEVICE_COOKIE_SAMESITE = "Strict"
    settings.DEVICE_COOKIE_SECURE = False
    morsel = login(client).cookies[COOKIE]
    assert morsel["domain"] == "example.com"
    assert morsel["path"] == "/app/"
    assert morsel["samesite"] == "Strict"
    assert not morsel["secure"]
