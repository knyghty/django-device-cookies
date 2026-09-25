import logging
import secrets
import time
import unicodedata
from unittest import mock

import pytest
from asgiref.sync import async_to_sync
from django.contrib.auth import _clean_credentials
from django.contrib.auth import aauthenticate
from django.contrib.auth import aget_user
from django.contrib.auth import authenticate
from django.contrib.auth import get_user_model
from django.contrib.auth.models import User
from django.contrib.auth.models import UserManager
from django.contrib.auth.signals import user_logged_in
from django.contrib.auth.signals import user_login_failed
from django.http import HttpRequest
from django.test import Client
from django.test import RequestFactory
from django.urls import reverse
from pytest_django.fixtures import Settings

from django_device_cookies import utils
from django_device_cookies.backends import DeviceCookieBackend
from django_device_cookies.models import NONCE_LENGTH
from django_device_cookies.models import FailedAuthenticationAttempt
from django_device_cookies.models import hash_username
from django_device_cookies.signals import lockout

from .helpers import COMBINED
from .helpers import COOKIE
from .helpers import DJANGO
from .helpers import GATE
from .helpers import LIMIT
from .helpers import PASSWORD
from .helpers import age
from .helpers import attempt
from .helpers import create_user
from .helpers import fail
from .helpers import logged_in
from .helpers import login
from .helpers import read_payload

pytestmark = pytest.mark.django_db


@pytest.fixture(
    autouse=True, params=[[GATE, DJANGO], [COMBINED]], ids=["gate", "combined"]
)
def backends(request: pytest.FixtureRequest, settings: Settings) -> None:
    settings.AUTHENTICATION_BACKENDS = request.param


def count_attempts(username: str | None = None, **filters: str) -> int:
    queryset = FailedAuthenticationAttempt.objects.filter(**filters)
    if username is not None:
        queryset = queryset.filter(key=hash_username(username))
    return queryset.count()


def test_failures_below_the_limit_do_not_lock(client: Client, user: User) -> None:
    fail(client, LIMIT - 1)
    assert logged_in(login(client))


def test_failures_at_the_limit_lock_untrusted_clients(
    client: Client, user: User
) -> None:
    fail(client)
    assert not logged_in(login(client))


def test_lockout_lifts_one_slot_at_a_time(client: Client, user: User) -> None:
    fail(client)
    oldest = FailedAuthenticationAttempt.objects.order_by("time", "pk")[:1]
    age(FailedAuthenticationAttempt.objects.filter(pk__in=oldest))
    assert logged_in(login(Client()))
    fail(Client(), 1)
    assert not logged_in(login(Client()))


def test_locked_attempt_hashes_the_password(client: Client, user: User) -> None:
    fail(client)
    with mock.patch("django_device_cookies.backends.make_password") as hasher:
        attempt(client, password="wrong again")
        authenticate(username="alice")
    hasher.assert_called_once_with("wrong again")


def test_attempts_during_lockout_are_not_recorded(client: Client, user: User) -> None:
    fail(client, LIMIT + 2)
    assert count_attempts() == LIMIT


def test_unknown_usernames_are_throttled_like_real_ones(client: Client) -> None:
    fail(client, LIMIT + 2, username="nobody")
    assert count_attempts(username="nobody", device="") == LIMIT
    assert FailedAuthenticationAttempt.objects.is_locked_out("nobody", "")


def test_login_issues_a_device_cookie(client: Client, user: User) -> None:
    morsel = login(client).cookies[COOKIE]
    assert morsel["httponly"]
    assert morsel["secure"]
    assert morsel["samesite"] == "Lax"
    assert morsel["max-age"] == 365 * 24 * 60 * 60
    assert morsel["path"] == "/"
    assert morsel["domain"] == ""
    first = read_payload(morsel.value)
    assert first["u"] == "alice"
    assert len(first["n"]) == NONCE_LENGTH
    assert read_payload(login(client).cookies[COOKIE].value)["n"] != first["n"]


@pytest.mark.parametrize("cookie", [False, True], ids=["untrusted", "device"])
def test_lockout_is_logged_and_signalled(
    client: Client, user: User, caplog: pytest.LogCaptureFixture, cookie: bool
) -> None:
    if cookie:
        login(client)
    caplog.set_level(logging.WARNING, logger="django_device_cookies")
    received: list[dict[str, object]] = []

    def receive(**kwargs: object) -> None:
        received.append(kwargs)

    lockout.connect(receive)
    fail(client, LIMIT + 2)
    assert len(received) == 1
    assert received[0]["username"] == "alice"
    request = received[0]["request"]
    assert isinstance(request, HttpRequest)
    assert request.path == reverse("login")
    device = received[0]["device"]
    assert isinstance(device, str)
    assert len(device) == (NONCE_LENGTH if cookie else 0)
    clients = "device" if cookie else "untrusted clients"
    assert caplog.messages == [f"Locked out {clients} for username 'alice'."]


def test_trusted_device_bypasses_untrusted_lockout(
    client: Client, trusted: Client
) -> None:
    fail(client)
    assert not logged_in(login(client))
    assert logged_in(login(trusted))


def test_locked_device_does_not_affect_untrusted_clients(trusted: Client) -> None:
    fail(trusted)
    assert not logged_in(login(trusted))
    assert logged_in(login(Client()))
    assert count_attempts(device="") == 0
    assert FailedAuthenticationAttempt.objects.exclude(device="").count() == LIMIT


def test_fabricated_cookies_share_the_untrusted_bucket(
    client: Client, user: User
) -> None:
    for _ in range(LIMIT):
        client.cookies[COOKIE] = secrets.token_hex(NONCE_LENGTH // 2)
        attempt(client)
    client.cookies[COOKIE] = "not even close"
    assert not logged_in(login(client))
    assert count_attempts(device="") == LIMIT


def test_tampered_cookie_is_untrusted(client: Client, trusted: Client) -> None:
    value = trusted.cookies[COOKIE].value
    fail(client)
    trusted.cookies[COOKIE] = value[:-1] + ("A" if value[-1] != "A" else "B")
    assert not logged_in(login(trusted))
    trusted.cookies[COOKIE] = value
    assert logged_in(login(trusted))


@pytest.mark.parametrize("other", ["bob", "ALICE"], ids=["other user", "merging name"])
def test_another_accounts_cookie_is_untrusted(
    client: Client, user: User, other: str
) -> None:
    create_user(other)
    impostor = Client()
    login(impostor, other)
    fail(client)
    client.cookies[COOKIE] = impostor.cookies[COOKIE].value
    assert not logged_in(login(client))


def test_cookie_is_trusted_for_a_case_insensitive_account(
    client: Client, trusted: Client
) -> None:
    with mock.patch.object(UserManager, "get_by_natural_key", by_iexact):
        fail(client)
        assert logged_in(login(trusted, "Alice"))


def by_iexact(manager: UserManager, username: str) -> User:
    return manager.get(username__iexact=username)


def by_accent_insensitive(manager: UserManager, username: str) -> User:
    ascii_name = unicodedata.normalize("NFKD", username).encode("ascii", "ignore")
    return manager.get(username=ascii_name.decode())


def test_spellings_that_reach_one_account_share_its_bucket(
    client: Client, user: User
) -> None:
    with mock.patch.object(UserManager, "get_by_natural_key", by_accent_insensitive):
        for spelling in ["alicé", "álice", "alicè", "àlice", "alíce"]:
            attempt(client, spelling)
        assert not logged_in(login(client))
    assert count_attempts(username="alice", device="") == LIMIT


def test_expired_cookie_is_untrusted(client: Client, trusted: Client) -> None:
    fail(client)
    future = time.time() + 366 * 24 * 60 * 60
    with mock.patch("django.core.signing.time.time", return_value=future):
        assert not logged_in(login(trusted))
    assert logged_in(login(trusted))


def test_key_rotation_keeps_cookies_valid(
    client: Client, trusted: Client, settings: Settings
) -> None:
    fail(client)
    settings.SECRET_KEY_FALLBACKS = [settings.SECRET_KEY]
    settings.SECRET_KEY = "rotated"
    assert logged_in(login(trusted))


def test_username_case_variants_share_a_bucket(client: Client, user: User) -> None:
    fail(client, LIMIT - 1, username="Alice")
    fail(client, 1, username="ALICE")
    assert not logged_in(login(client))


def test_authenticate_without_a_request_counts_as_untrusted(user: User) -> None:
    for _ in range(LIMIT):
        assert authenticate(username="alice", password="wrong") is None
    assert authenticate(username="alice", password=PASSWORD) is None
    assert count_attempts(username="alice", device="") == LIMIT


def test_credentials_without_a_username_are_ignored(
    user: User, rf: RequestFactory
) -> None:
    request = rf.get("/")
    assert authenticate(request, remote_user="alice") is None
    assert authenticate(request, token="abc") is None
    assert count_attempts() == 0


def test_username_field_credential_is_gated(user: User, rf: RequestFactory) -> None:
    request = rf.get("/")
    with mock.patch.object(get_user_model(), "USERNAME_FIELD", "email"):
        for _ in range(LIMIT + 2):
            authenticate(request, email="alice@example.com", password="wrong")
    assert count_attempts(username="alice@example.com", device="") == LIMIT


def test_masked_username_field_is_throttled_with_a_request(
    user: User, rf: RequestFactory
) -> None:
    request = rf.get("/")
    with (
        mock.patch.object(get_user_model(), "USERNAME_FIELD", "api_key"),
        mock.patch.object(User, "get_username", get_plain_username),
        mock.patch.object(UserManager, "get_by_natural_key", by_username),
    ):
        for _ in range(LIMIT + 2):
            authenticate(request, api_key="alice", password="wrong")
        assert authenticate(request, api_key="alice", password=PASSWORD) is None
    assert count_attempts(username="alice", device="") == LIMIT


def by_username(manager: UserManager, username: str) -> User:
    return manager.get(username=username)


def get_plain_username(user: User) -> str:
    return str(user.username)


def test_masked_username_field_records_nothing_without_a_request(
    user: User, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.WARNING, logger="django_device_cookies")
    with mock.patch.object(get_user_model(), "USERNAME_FIELD", "api_key"):
        credentials = _clean_credentials({"api_key": "alice", "password": "wrong"})
        for _ in range(LIMIT + 2):
            user_login_failed.send(sender=None, credentials=credentials)
    assert count_attempts() == 0
    assert caplog.messages == []


def test_stale_stash_is_ignored_for_another_username(
    user: User, rf: RequestFactory
) -> None:
    request = rf.get("/")
    utils.stash_bucket(request, {"username": "alice"}, ("alice", "x" * 32))
    user_login_failed.send(
        sender=None, credentials={"username": "bob"}, request=request
    )
    assert count_attempts(username="bob", device="") == 1
    assert count_attempts(username="alice") == 0


def test_async_authenticate_is_gated(user: User, rf: RequestFactory) -> None:
    request = rf.get("/")
    credentials = {"username": "alice", "password": PASSWORD}
    assert async_to_sync(aauthenticate)(request, **credentials) == user
    fail(Client())
    assert async_to_sync(aauthenticate)(request, **credentials) is None
    assert async_to_sync(aauthenticate)(request, token="abc") is None
    assert async_to_sync(aauthenticate)(request, username="nobody") is None
    assert count_attempts(username="nobody", device="") == 1


def test_async_authenticate_trusts_a_device(
    trusted: Client, rf: RequestFactory, settings: Settings
) -> None:
    request = rf.get("/")
    request.COOKIES[COOKIE] = trusted.cookies[COOKIE].value
    credentials = {"username": "alice", "password": PASSWORD}
    fail(Client())
    assert async_to_sync(aauthenticate)(request, **credentials) is not None
    settings.DEVICE_COOKIE_REVOKE_AFTER_FAILURES = 1
    fail(trusted, 1)
    assert async_to_sync(aauthenticate)(request, **credentials) is None


def test_signals_without_a_request(user: User) -> None:
    user_logged_in.send(sender=type(user), user=user)
    user_login_failed.send(sender=None, credentials={"username": "alice"})
    assert count_attempts(username="alice", device="") == 1


def test_force_login_works(client: Client, user: User) -> None:
    client.force_login(user)
    assert client.get(reverse("login")).wsgi_request.user == user


def test_session_backed_by_the_gate_loads_the_user(
    client: Client, user: User, settings: Settings
) -> None:
    settings.AUTHENTICATION_BACKENDS = [GATE, DJANGO]
    client.force_login(user, backend=GATE)
    request = client.get(reverse("login")).wsgi_request
    assert request.user == user
    assert async_to_sync(aget_user)(request) == user
    assert DeviceCookieBackend().get_user(0) is None
