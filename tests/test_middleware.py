from http import HTTPStatus

import pytest
from django.contrib.auth.models import User
from django.test import Client
from django.urls import reverse
from pytest_django.fixtures import Settings

from .helpers import COOKIE
from .helpers import attempt
from .helpers import login
from .helpers import read_payload

pytestmark = pytest.mark.django_db


def test_cookie_is_issued_without_authentication_middleware(
    client: Client, user: User, settings: Settings
) -> None:
    settings.MIDDLEWARE = [
        path for path in settings.MIDDLEWARE if "AuthenticationMiddleware" not in path
    ]
    response = login(client)
    assert response.status_code == HTTPStatus.FOUND
    assert COOKIE in response.cookies


def test_no_cookie_without_a_login(client: Client, user: User) -> None:
    assert COOKIE not in client.get(reverse("login")).cookies


def test_no_cookie_after_a_failed_login(client: Client, user: User) -> None:
    assert COOKIE not in attempt(client).cookies


def test_login_through_a_request_wrapper_issues_a_cookie(
    client: Client, user: User
) -> None:
    response = login(client, url="login-wrapped")
    assert read_payload(response.cookies[COOKIE].value)["u"] == "alice"


def test_login_then_logout_issues_for_the_user_who_logged_in(
    client: Client, user: User
) -> None:
    response = login(client, url="login-logout")
    assert read_payload(response.cookies[COOKIE].value)["u"] == "alice"
