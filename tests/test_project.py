from http import HTTPStatus

from django.core.management import call_command
from django.test import Client

from django_device_cookies.models import FailedAuthenticationAttempt
from django_device_cookies.models import hash_username


def test_migrations_match_models(db: None) -> None:
    call_command(
        "makemigrations", "device_cookies", check=True, dry_run=True, verbosity=0
    )


def test_admin_changelist_renders(admin_client: Client) -> None:
    key = hash_username("alice")
    FailedAuthenticationAttempt.objects.create(key=key)
    FailedAuthenticationAttempt.objects.create(key=hash_username("bob"), device="abc")
    url = "/admin/device_cookies/failedauthenticationattempt/"
    assert admin_client.get(url).status_code == HTTPStatus.OK
    for query in ["Alice", key]:
        text = admin_client.get(url, {"q": query}).text
        assert key in text
        assert hash_username("bob") not in text
