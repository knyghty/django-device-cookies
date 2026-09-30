from http import HTTPStatus

import pytest
from allauth.account.forms import default_token_generator
from allauth.account.internal.flows.password_reset_by_code import (
    PASSWORD_RESET_VERIFICATION_SESSION_KEY,
)
from allauth.account.utils import user_pk_to_url_str
from django.contrib.auth.models import User
from django.test import Client
from django.urls import reverse
from pytest_django.fixtures import Settings

from .helpers import COOKIE
from .helpers import GATE
from .helpers import PASSWORD
from .helpers import Response
from .helpers import fail
from .helpers import logged_in
from .helpers import login
from .helpers import read_payload

pytestmark = pytest.mark.django_db

ALLAUTH = "allauth.account.auth_backends.AuthenticationBackend"


@pytest.fixture(autouse=True)
def backends(settings: Settings) -> None:
    settings.AUTHENTICATION_BACKENDS = [GATE, ALLAUTH]


@pytest.fixture
def emailed(user: User) -> User:
    User.objects.filter(pk=user.pk).update(email="alice@example.com")
    return user


def make_key_link(user: User) -> str:
    key = default_token_generator.make_token(user)
    kwargs = {"uidb36": user_pk_to_url_str(user), "key": key}
    return reverse("account_reset_password_from_key", kwargs=kwargs)


def allauth_login(client: Client, login: str, password: str = PASSWORD) -> Response:
    return client.post(reverse("account_login"), {"login": login, "password": password})


def test_key_link_trusts_the_device(client: Client, user: User) -> None:
    fail(Client())
    response = client.get(make_key_link(user), follow=True)
    assert response.status_code == HTTPStatus.OK
    assert read_payload(response.cookies[COOKIE].value)["u"] == "alice"
    assert logged_in(login(client))


def test_reopening_a_key_link_gives_the_same_device(client: Client, user: User) -> None:
    link = make_key_link(user)
    first = read_payload(client.get(link, follow=True).cookies[COOKIE].value)
    again = read_payload(client.get(link, follow=True).cookies[COOKIE].value)
    assert first["n"] == again["n"]


def test_reset_code_trusts_the_device(client: Client, emailed: User) -> None:
    fail(Client())
    client.post(reverse("account_reset_password"), {"email": "alice@example.com"})
    code = client.session[PASSWORD_RESET_VERIFICATION_SESSION_KEY]["code"]
    response = client.post(
        reverse("account_confirm_password_reset_code"), {"code": code}
    )
    assert response.status_code == HTTPStatus.FOUND
    assert read_payload(response.cookies[COOKIE].value)["u"] == "alice"
    assert logged_in(login(client))


def test_wrong_reset_code_issues_nothing(client: Client, emailed: User) -> None:
    client.post(reverse("account_reset_password"), {"email": "alice@example.com"})
    response = client.post(
        reverse("account_confirm_password_reset_code"), {"code": "nope"}
    )
    assert response.status_code == HTTPStatus.OK
    assert COOKIE not in response.cookies


def test_invalid_key_issues_nothing(client: Client, user: User) -> None:
    link = make_key_link(user).replace(user_pk_to_url_str(user), "zz")
    response = client.get(link, follow=True)
    assert response.status_code == HTTPStatus.OK
    assert COOKIE not in response.cookies


def test_login_form_shows_the_lockout_message(client: Client, user: User) -> None:
    fail(client)
    response = allauth_login(client, "alice")
    assert response.status_code == HTTPStatus.OK
    assert "Too many failed attempts." in response.text
    assert "password reset" in response.text


def test_email_login_is_throttled_per_account(client: Client, emailed: User) -> None:
    for _ in range(3):
        allauth_login(client, "Alice@Example.com", "wrong")
    for _ in range(2):
        allauth_login(client, "alice", "wrong")
    assert (
        "Too many failed attempts." in allauth_login(client, "alice@example.com").text
    )
    assert "Too many failed attempts." in allauth_login(client, "alice").text


def test_unknown_email_is_throttled(client: Client, user: User) -> None:
    for _ in range(5):
        allauth_login(client, "nobody@example.com", "wrong")
    assert (
        "Too many failed attempts." in allauth_login(client, "nobody@example.com").text
    )


def test_email_login_trusts_the_device(client: Client, emailed: User) -> None:
    assert logged_in(allauth_login(client, "alice@example.com"))
    fail(Client())
    assert logged_in(allauth_login(client, "alice@example.com"))
