from http import HTTPStatus

import pytest
from asgiref.sync import async_to_sync
from django.contrib.auth.models import User
from django.test import AsyncClient
from django.test import Client
from django.urls import reverse
from pytest_django.fixtures import Settings

from .helpers import COOKIE
from .helpers import PASSWORD
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


@pytest.mark.parametrize(
    "url",
    ["login-wrapped", "login-logout"],
    ids=["request wrapper", "login then logout"],
)
def test_login_issues_a_cookie_for_the_user(
    client: Client, user: User, url: str
) -> None:
    response = login(client, url=url)
    assert read_payload(response.cookies[COOKIE].value)["u"] == "alice"


def test_async_request_issues_a_cookie(async_client: AsyncClient, user: User) -> None:
    data = {"username": "alice", "password": PASSWORD}
    response = async_to_sync(async_client.post)(reverse("login"), data)
    assert read_payload(response.cookies[COOKIE].value)["u"] == "alice"
