import pytest
from django.utils import timezone

from django_device_cookies.models import FailedAuthenticationAttempt
from django_device_cookies.models import hash_username

from .helpers import LIMIT
from .helpers import create_stale

pytestmark = pytest.mark.django_db


@pytest.mark.parametrize(("device", "label"), [("", "untrusted"), ("abc", "abc")])
def test_str(device: str, label: str) -> None:
    now = timezone.now()
    attempt = FailedAuthenticationAttempt(key="abc123", device=device, time=now)
    assert str(attempt) == f"abc123 ({label}) at {now}"


def test_record_failure_reports_the_failure_that_locks() -> None:
    attempts = FailedAuthenticationAttempt.objects
    for _ in range(LIMIT - 1):
        assert not attempts.record_failure("alice", "")
    assert not attempts.is_locked_out("alice", "")
    assert attempts.record_failure("alice", "")
    assert attempts.is_locked_out("alice", "")
    assert not attempts.record_failure("alice", "")
    assert attempts.count() == LIMIT


def test_buckets_are_independent() -> None:
    attempts = FailedAuthenticationAttempt.objects
    for _ in range(LIMIT):
        attempts.record_failure("alice", "")
    assert not attempts.is_locked_out("alice", "nonce")
    assert not attempts.is_locked_out("bob", "")


def test_stale_attempts_do_not_count() -> None:
    for _ in range(LIMIT):
        create_stale(key=hash_username("alice"))
    assert not FailedAuthenticationAttempt.objects.is_locked_out("alice", "")
