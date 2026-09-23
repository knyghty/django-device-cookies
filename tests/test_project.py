from http import HTTPStatus

from django.core.management import call_command
from django.test import Client

from django_device_cookies.models import FailedAuthenticationAttempt


def test_migrations_match_models(db: None) -> None:
    call_command(
        "makemigrations", "device_cookies", check=True, dry_run=True, verbosity=0
    )


def test_admin_changelist_renders(admin_client: Client) -> None:
    FailedAuthenticationAttempt.objects.create(username="alice")
    FailedAuthenticationAttempt.objects.create(username="alice", device="abc")
    url = "/admin/device_cookies/failedauthenticationattempt/?q=alice"
    assert admin_client.get(url).status_code == HTTPStatus.OK
