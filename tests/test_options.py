import logging
from unittest import mock

import pytest
from django.contrib.auth.models import User
from django.contrib.auth.models import UserManager
from django.test import Client
from pytest_django.fixtures import Settings

from django_device_cookies.models import FailedAuthenticationAttempt
from django_device_cookies.models import hash_username

from .helpers import COOKIE
from .helpers import LIMIT
from .helpers import age
from .helpers import create_user
from .helpers import fail
from .helpers import logged_in
from .helpers import login
from .helpers import read_payload
from .test_login import by_iexact

pytestmark = pytest.mark.django_db


def test_one_cookie_per_browser_by_default(client: Client, user: User) -> None:
    create_user("bob")
    login(client)
    login(client, "bob")
    assert read_payload(client.cookies[COOKIE].value)["u"] == "bob"
    fail(Client())
    assert not logged_in(login(client))


def test_one_cookie_per_user(client: Client, user: User, settings: Settings) -> None:
    settings.DEVICE_COOKIE_PER_USER = True
    create_user("bob")
    login(client)
    login(client, "bob")
    assert COOKIE not in client.cookies
    fail(Client())
    fail(Client(), username="bob")
    assert logged_in(login(client))
    assert logged_in(login(client, "bob"))
    with mock.patch.object(UserManager, "get_by_natural_key", by_iexact):
        assert logged_in(login(client, "Alice"))


def test_revocation(
    trusted: Client, settings: Settings, caplog: pytest.LogCaptureFixture
) -> None:
    settings.DEVICE_COOKIE_REVOKE_AFTER_FAILURES = LIMIT + 1
    caplog.set_level(logging.WARNING, logger="django_device_cookies")
    fail(trusted)
    age(FailedAuthenticationAttempt.objects.all())
    fail(trusted, 1)
    assert f"Revoked a device of key {hash_username('alice')}." in caplog.messages
    fail(Client())
    assert not logged_in(login(trusted))
    assert not FailedAuthenticationAttempt.objects.filter_stale().exists()


def test_revocation_off_by_default(trusted: Client) -> None:
    fail(trusted)
    age(FailedAuthenticationAttempt.objects.all())
    fail(trusted, 1)
    assert FailedAuthenticationAttempt.objects.filter_stale().count() == LIMIT
