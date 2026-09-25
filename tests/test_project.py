from http import HTTPStatus

import pytest
from django.core.management import call_command
from django.test import Client

from django_device_cookies.models import FailedAuthenticationAttempt
from django_device_cookies.models import hash_username


def test_migrations_match_models(db: None) -> None:
    call_command(
        "makemigrations", "device_cookies", check=True, dry_run=True, verbosity=0
    )


URL = "/admin/device_cookies/failedauthenticationattempt/"


@pytest.fixture
def attempts(db: None) -> None:
    FailedAuthenticationAttempt.objects.record_failure("alice", "")
    FailedAuthenticationAttempt.objects.record_failure("bob", "abc")


def test_admin_changelist_renders(admin_client: Client, attempts: None) -> None:
    response = admin_client.get(URL)
    assert response.status_code == HTTPStatus.OK
    assert "Enter all or part of the username, or a key." in response.text


@pytest.mark.parametrize(
    "query", ["alice", "ALI", "lic", hash_username("alice")], ids=str.lower
)
def test_admin_search(admin_client: Client, attempts: None, query: str) -> None:
    rows = admin_client.get(URL, {"q": query}).context["cl"].result_list
    assert [row.username for row in rows] == ["alice"]
