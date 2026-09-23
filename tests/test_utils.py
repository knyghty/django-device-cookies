import pytest
from django.core import signing
from django.http import HttpRequest
from django.http import HttpResponse
from django.test import RequestFactory

from django_device_cookies import utils

from .helpers import COOKIE
from .helpers import read_payload

pytestmark = pytest.mark.django_db


@pytest.mark.parametrize(
    ("username", "expected"),
    [
        ("ALICE", "alice"),
        ("ﬁsh", "fish"),
        ("Straße", "strasse"),
        (123, "123"),
        ("a" * 300, "a" * 255),
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
        ({"username": "Alice"}, ("alice", "")),
        ({"username": "a" * 300}, ("a" * 255, "")),
        ({}, None),
    ],
)
def test_get_bucket(
    credentials: dict[str, object], expected: tuple[str, str] | None
) -> None:
    assert utils.get_bucket(None, credentials) == expected


def issue_cookie(username: str = "alice") -> str:
    response = HttpResponse()
    utils.issue_device_cookie(response, username, None)
    return response.cookies[COOKIE].value


def make_request(rf: RequestFactory, cookie: str | None = None) -> HttpRequest:
    request = rf.get("/")
    if cookie is not None:
        request.COOKIES[COOKIE] = cookie
    return request


def test_no_request() -> None:
    assert utils.get_device(None, "alice") == ""


def test_no_cookie(rf: RequestFactory) -> None:
    assert utils.get_device(make_request(rf), "alice") == ""


def test_empty_cookie(rf: RequestFactory) -> None:
    assert utils.get_device(make_request(rf, ""), "alice") == ""


def test_valid_cookie(rf: RequestFactory) -> None:
    cookie = issue_cookie()
    assert (
        utils.get_device(make_request(rf, cookie), "alice") == read_payload(cookie)["n"]
    )


def test_cookie_for_a_case_variant_is_untrusted(rf: RequestFactory) -> None:
    assert utils.get_device(make_request(rf, issue_cookie("Alice")), "alice") == ""


def test_other_users_cookie(rf: RequestFactory) -> None:
    assert utils.get_device(make_request(rf, issue_cookie("bob")), "alice") == ""


def test_garbage(rf: RequestFactory) -> None:
    assert utils.get_device(make_request(rf, "garbage"), "alice") == ""


def test_other_salt(rf: RequestFactory) -> None:
    cookie = signing.dumps({"u": "alice", "n": "x" * 32})
    assert utils.get_device(make_request(rf, cookie), "alice") == ""


@pytest.mark.parametrize(
    "malformed",
    [
        ["alice", "x" * 32],
        {"n": "x" * 32},
        {"u": "alice", "n": 1},
        {"u": "alice", "n": "short"},
    ],
)
def test_malformed_payloads_are_untrusted(
    rf: RequestFactory, malformed: object
) -> None:
    cookie = signing.dumps(malformed, salt=utils.SALT)
    assert utils.get_device(make_request(rf, cookie), "alice") == ""
