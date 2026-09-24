import datetime
from http import HTTPStatus
from http.cookies import SimpleCookie
from typing import Protocol

from django.contrib.auth import SESSION_KEY
from django.contrib.auth.models import User
from django.core import signing
from django.db.models import F
from django.db.models import QuerySet
from django.test import Client
from django.urls import reverse
from django.utils import timezone

from django_device_cookies import utils
from django_device_cookies.models import FailedAuthenticationAttempt

COOKIE = "django_device"
PASSWORD = "correct horse battery staple"
LIMIT = 5
STALE = datetime.timedelta(minutes=15, seconds=1)

GATE = "django_device_cookies.backends.DeviceCookieBackend"
COMBINED = "django_device_cookies.backends.DeviceCookieModelBackend"
DJANGO = "django.contrib.auth.backends.ModelBackend"


class Response(Protocol):
    status_code: int
    cookies: SimpleCookie
    client: Client
    redirect_chain: list[tuple[str, int]]

    def __getitem__(self, header: str) -> str: ...


def create_user(username: str) -> User:
    return User.objects.create_user(username, password=PASSWORD)


def attempt(
    client: Client, username: str = "alice", password: str = "wrong", url: str = "login"
) -> Response:
    return client.post(reverse(url), {"username": username, "password": password})


def fail(client: Client, times: int = LIMIT, username: str = "alice") -> None:
    for _ in range(times):
        attempt(client, username)


def login(client: Client, username: str = "alice", url: str = "login") -> Response:
    return attempt(client, username, PASSWORD, url)


def logged_in(response: Response) -> bool:
    redirected = response.status_code == HTTPStatus.FOUND
    return redirected and SESSION_KEY in response.client.session


def read_payload(cookie: str) -> dict[str, str]:
    return signing.loads(cookie, salt=utils.SALT)


def age(queryset: QuerySet, delta: datetime.timedelta = STALE) -> None:
    queryset.update(time=F("time") - delta)


def create_stale(**kwargs: object) -> FailedAuthenticationAttempt:
    time = timezone.now() - STALE
    return FailedAuthenticationAttempt.objects.create(time=time, **kwargs)
