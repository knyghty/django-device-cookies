from unittest import mock

import pytest
from allauth.account.models import EmailAddress
from django.apps import apps
from django.contrib.auth.models import User
from django.contrib.auth.models import UserManager
from django.core import signing
from django.core.exceptions import MultipleObjectsReturned
from django.http import HttpRequest
from django.http import HttpResponse
from django.test import RequestFactory
from pytest_django.fixtures import Settings

from django_device_cookies import utils

from .helpers import COOKIE
from .helpers import create_user
from .helpers import read_payload

pytestmark = pytest.mark.django_db


@pytest.mark.parametrize(
    ("username", "expected"),
    [
        ("ALICE", "alice"),
        ("ﬁsh", "fish"),
        ("Straße", "strasse"),
        (123, "123"),
    ],
)
def test_normalize_username(username: object, expected: str) -> None:
    assert utils.normalize_username(username) == expected


@pytest.mark.parametrize(
    ("credentials", "expected"),
    [
        ({"username": "Alice", "password": "x"}, "Alice"),
        ({"username": 123}, "123"),
        ({"email": "alice@example.com"}, "alice@example.com"),
        ({"phone": "+1"}, None),
        ({"password": "x"}, None),
        ({}, None),
    ],
)
def test_get_username(credentials: dict[str, object], expected: str | None) -> None:
    assert utils.get_username(credentials) == expected


@pytest.mark.parametrize(
    ("credentials", "expected"),
    [
        ({"username": "Alice"}, ("alice", "", None)),
        ({"username": "a" * 300}, ("a" * 300, "", None)),
        ({"username": "nobody@example.com"}, ("nobody@example.com", "", None)),
        ({"email": "nobody"}, ("nobody", "", None)),
        ({}, None),
    ],
)
def test_get_bucket(
    credentials: dict[str, object], expected: tuple[str, str] | None
) -> None:
    assert utils.get_bucket(None, credentials) == expected


def test_find_user(user: User) -> None:
    User.objects.filter(pk=user.pk).update(email="alice@example.com")
    carol = User.objects.create_user("carol@example.com", email="carol@example.com")
    dave = create_user("dave@example.com")
    assert utils.find_user("alice") == user
    assert utils.find_user("Alice@Example.com") == user
    assert utils.find_user("carol@example.com") == carol
    assert utils.find_user("dave@example.com") == dave
    assert utils.find_user("nobody@example.com") is None
    assert utils.find_user("nobody") is None


def test_find_user_with_a_disputed_identifier(user: User) -> None:
    User.objects.filter(pk=user.pk).update(email="alice@example.com")
    create_user("alice@example.com")
    assert utils.find_user("alice@example.com") is None
    User.objects.update(email="alice@example.com")
    assert utils.find_user("alice@example.com") is None


def test_find_user_resolves_an_address_like_allauth(user: User) -> None:
    address = EmailAddress.objects.create(
        user=user, email="alice2@example.com", verified=True
    )
    User.objects.create_user("mallory", email="alice2@example.com")
    assert utils.find_user("alice2@example.com") == user
    address.verified = False
    address.save()
    assert utils.find_user("alice2@example.com") is None


def test_find_user_follows_allauth_login_methods(
    user: User, settings: Settings
) -> None:
    User.objects.filter(pk=user.pk).update(email="alice@example.com")
    settings.ACCOUNT_LOGIN_METHODS = {"username"}
    assert utils.find_user("alice@example.com") is None
    assert utils.find_user("ALICE") == user
    settings.ACCOUNT_LOGIN_METHODS = {"email"}
    assert utils.find_user("alice@example.com") == user
    assert utils.find_user("ALICE") is None


def test_find_user_without_allauth(user: User) -> None:
    User.objects.filter(pk=user.pk).update(email="alice@example.com")
    with mock.patch.object(apps, "is_installed", return_value=False):
        assert utils.find_user("alice") == user
        assert utils.find_user("alice@example.com") is None


def test_find_user_with_a_duplicated_username(user: User) -> None:
    with mock.patch.object(
        UserManager, "get_by_natural_key", side_effect=MultipleObjectsReturned
    ):
        assert utils.find_user("alice") is None


def issue_cookie(user: User) -> str:
    response = HttpResponse()
    utils.issue_device_cookie(response, utils.build_payload(user))
    return response.cookies[COOKIE].value


def make_request(rf: RequestFactory, cookie: str | None = None) -> HttpRequest:
    request = rf.get("/")
    if cookie is not None:
        request.COOKIES[COOKIE] = cookie
    return request


def test_no_request(user: User) -> None:
    assert utils.get_device(None, user) == ""


def test_no_user(rf: RequestFactory, user: User) -> None:
    assert utils.get_device(make_request(rf, issue_cookie(user)), None) == ""


def test_no_cookie(rf: RequestFactory, user: User) -> None:
    assert utils.get_device(make_request(rf), user) == ""


def test_empty_cookie(rf: RequestFactory, user: User) -> None:
    assert utils.get_device(make_request(rf, ""), user) == ""


def test_valid_cookie(rf: RequestFactory, user: User) -> None:
    cookie = issue_cookie(user)
    assert utils.get_device(make_request(rf, cookie), user) == read_payload(cookie)["n"]


@pytest.mark.parametrize("other", ["bob", "Alice"])
def test_another_accounts_cookie(rf: RequestFactory, user: User, other: str) -> None:
    cookie = issue_cookie(create_user(other))
    assert utils.get_device(make_request(rf, cookie), user) == ""


def test_cookie_for_a_deleted_account_is_untrusted(
    rf: RequestFactory, user: User
) -> None:
    cookie = issue_cookie(user)
    user.delete()
    assert utils.get_device(make_request(rf, cookie), create_user("alice")) == ""


def test_garbage(rf: RequestFactory, user: User) -> None:
    assert utils.get_device(make_request(rf, "garbage"), user) == ""


def test_other_salt(rf: RequestFactory, user: User) -> None:
    cookie = signing.dumps(utils.build_payload(user))
    assert utils.get_device(make_request(rf, cookie), user) == ""


@pytest.mark.parametrize(
    "malformed",
    [
        ["alice", "1", "x" * 32],
        {"n": "x" * 32},
        {"u": "alice", "n": "x" * 32},
        {"u": "alice", "i": "0", "n": "x" * 32},
        {"u": "alice", "i": "1", "n": 1},
        {"u": "alice", "i": "1", "n": "short"},
    ],
)
def test_malformed_payloads_are_untrusted(
    rf: RequestFactory, user: User, malformed: object
) -> None:
    cookie = signing.dumps(malformed, salt=utils.SALT)
    assert utils.get_device(make_request(rf, cookie), user) == ""
