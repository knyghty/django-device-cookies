from http import HTTPStatus

import pytest
from django.contrib.auth.models import User
from django.contrib.auth.tokens import default_token_generator
from django.test import Client
from django.urls import reverse
from django.utils.encoding import force_bytes
from django.utils.http import urlsafe_base64_encode
from pytest_django.fixtures import Settings

from .helpers import COOKIE
from .helpers import Response
from .helpers import fail
from .helpers import logged_in
from .helpers import login
from .helpers import read_payload

pytestmark = pytest.mark.django_db


def make_reset_link(user: User, token: str | None = None) -> str:
    uid = urlsafe_base64_encode(force_bytes(user.pk))
    token = token or default_token_generator.make_token(user)
    return reverse("password_reset_confirm", kwargs={"uidb64": uid, "token": token})


def open_link(client: Client, user: User) -> Response:
    return client.get(make_reset_link(user), follow=True)


def test_valid_link_trusts_the_device_without_a_password_change(
    client: Client, user: User
) -> None:
    fail(Client())
    response = open_link(client, user)
    assert response.status_code == HTTPStatus.OK
    assert read_payload(response.cookies[COOKIE].value)["u"] == "alice"
    assert logged_in(login(client))


def test_reopening_a_link_gives_the_same_device(client: Client, user: User) -> None:
    link = make_reset_link(user)
    first = read_payload(client.get(link, follow=True).cookies[COOKIE].value)
    again = read_payload(client.get(link, follow=True).cookies[COOKIE].value)
    assert again == first


def test_setting_a_new_password_works(client: Client, user: User) -> None:
    opened = open_link(client, user)
    password = {
        "new_password1": "a new passphrase",
        "new_password2": "a new passphrase",
    }
    response = client.post(opened.redirect_chain[-1][0], password)
    assert response.status_code == HTTPStatus.FOUND
    assert response["Location"] == reverse("password_reset_complete")


def test_link_works_with_login_required_middleware(
    client: Client, user: User, settings: Settings
) -> None:
    settings.MIDDLEWARE = [
        *settings.MIDDLEWARE,
        "django.contrib.auth.middleware.LoginRequiredMiddleware",
    ]
    response = open_link(client, user)
    assert response.status_code == HTTPStatus.OK
    assert COOKIE in response.cookies


def test_invalid_link_issues_nothing(client: Client, user: User) -> None:
    response = client.get(make_reset_link(user, token="abc-def"))
    assert response.status_code == HTTPStatus.OK
    assert COOKIE not in response.cookies
