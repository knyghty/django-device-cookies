from io import StringIO

import pytest
from django.core.management import call_command

from django_device_cookies.models import FailedAuthenticationAttempt

from .helpers import create_stale

pytestmark = pytest.mark.django_db


def clear(**options: object) -> str:
    out = StringIO()
    call_command("clear_device_cookie_attempts", stdout=out, **options)
    return out.getvalue()


def test_deletes_only_stale_attempts() -> None:
    create_stale(username="alice")
    fresh = FailedAuthenticationAttempt.objects.create(username="alice")
    assert clear() == "Deleted 1 failed authentication attempt.\n"
    assert list(FailedAuthenticationAttempt.objects.all()) == [fresh]


def test_quiet() -> None:
    create_stale(username="alice")
    assert clear(verbosity=0) == ""
