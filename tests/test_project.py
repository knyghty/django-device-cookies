from http import HTTPStatus

import pytest
from django.contrib import admin
from django.contrib.auth import get_user_model
from django.core.management import call_command
from django.test import Client

from django_device_cookies.admin import prefix_user_field
from django_device_cookies.models import FailedAuthenticationAttempt

from .helpers import create_user


def test_migrations_match_models(db: None) -> None:
    call_command(
        "makemigrations", "device_cookies", check=True, dry_run=True, verbosity=0
    )


URL = "/admin/device_cookies/failedauthenticationattempt/"


@pytest.fixture
def attempts(db: None) -> None:
    alice = create_user("alice")
    get_user_model().objects.filter(pk=alice.pk).update(email="alice@example.com")
    FailedAuthenticationAttempt.objects.record_failure("alice", "", alice)
    FailedAuthenticationAttempt.objects.record_failure("nobody", "")


def search(admin_client: Client, query: str) -> list[str]:
    rows = admin_client.get(URL, {"q": query}).context["cl"].result_list
    return sorted(str(row.user) if row.user else "no user" for row in rows)


def test_admin_changelist_renders(admin_client: Client, attempts: None) -> None:
    response = admin_client.get(URL)
    assert response.status_code == HTTPStatus.OK
    assert "or enter the exact username for attempts without one." in response.text


@pytest.mark.parametrize(
    ("query", "expected"),
    [
        ("ali", ["alice"]),
        ("example.com", ["alice"]),
        ("Nobody", ["no user"]),
        ("nob", []),
        ("", ["alice", "no user"]),
    ],
    ids=["username part", "email part", "unknown name", "unknown part", "empty"],
)
def test_admin_search(
    admin_client: Client, attempts: None, query: str, expected: list[str]
) -> None:
    assert search(admin_client, query) == expected


def test_admin_search_without_a_user_admin(
    admin_client: Client, attempts: None
) -> None:
    user_admin = admin.site._registry.pop(get_user_model())
    try:
        assert search(admin_client, "ali") == ["alice"]
    finally:
        admin.site._registry[get_user_model()] = user_admin


@pytest.mark.parametrize(
    ("field", "expected"),
    [("email", "user__email"), ("^username", "^user__username")],
)
def test_prefix_user_field(field: str, expected: str) -> None:
    assert prefix_user_field(field) == expected
