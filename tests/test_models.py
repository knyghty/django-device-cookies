import pytest
from django.contrib.auth.models import User
from django.utils import timezone

from django_device_cookies.models import Bucket
from django_device_cookies.models import FailedAuthenticationAttempt
from django_device_cookies.models import hash_username

from .helpers import LIMIT
from .helpers import create_stale

pytestmark = pytest.mark.django_db

ALICE = Bucket("alice", "")


@pytest.mark.parametrize(("device", "label"), [("", "untrusted"), ("abc", "abc")])
def test_str(user: User, device: str, label: str) -> None:
    now = timezone.now()
    attempt = FailedAuthenticationAttempt(key="abc123", device=device, time=now)
    assert str(attempt) == f"abc123 ({label}) at {now}"
    attempt = FailedAuthenticationAttempt(user=user, device=device, time=now)
    assert str(attempt) == f"alice ({label}) at {now}"


def test_bucket_username(user: User) -> None:
    assert Bucket("Alice@Example.com", "", user).username == "alice"
    assert ALICE.username == "alice"


def test_deleting_the_user_keeps_the_lockout(user: User) -> None:
    attempts = FailedAuthenticationAttempt.objects
    for _ in range(LIMIT):
        attempts.record_failure(Bucket("alice", "", user))
    user.delete()
    assert attempts.filter(user=None).count() == LIMIT
    assert attempts.is_locked_out(ALICE)


def test_record_failure_reports_the_failure_that_locks() -> None:
    attempts = FailedAuthenticationAttempt.objects
    for _ in range(LIMIT - 1):
        assert not attempts.record_failure(ALICE)
    assert not attempts.is_locked_out(ALICE)
    assert attempts.record_failure(ALICE)
    assert attempts.is_locked_out(ALICE)
    assert not attempts.record_failure(ALICE)
    assert attempts.count() == LIMIT


def test_another_identifier_is_recorded_until_it_reaches_the_limit(
    user: User,
) -> None:
    attempts = FailedAuthenticationAttempt.objects
    email = Bucket("alice@example.com", "", user)
    for _ in range(LIMIT):
        attempts.record_failure(Bucket("alice", "", user))
    assert attempts.is_locked_out(email)
    assert not attempts.is_identifier_locked_out(email)
    for _ in range(LIMIT):
        assert not attempts.record_failure(email)
    assert attempts.is_identifier_locked_out(email)
    assert not attempts.record_failure(email)
    assert attempts.count() == 2 * LIMIT


def test_buckets_are_independent() -> None:
    attempts = FailedAuthenticationAttempt.objects
    for _ in range(LIMIT):
        attempts.record_failure(ALICE)
    assert not attempts.is_locked_out(Bucket("alice", "nonce"))
    assert not attempts.is_locked_out(Bucket("bob", ""))


def test_stale_attempts_do_not_count() -> None:
    for _ in range(LIMIT):
        create_stale(key=hash_username("alice"))
    assert not FailedAuthenticationAttempt.objects.is_locked_out(ALICE)
