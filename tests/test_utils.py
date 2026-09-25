import pytest
from django.contrib.auth.models import User
from django.core import signing
from django.http import HttpRequest
from django.http import HttpResponse
from django.test import RequestFactory

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
        ({}, None),
    ],
)
def test_get_bucket(
    credentials: dict[str, object], expected: tuple[str, str] | None
) -> None:
    assert utils.get_bucket(None, credentials) == expected


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
