from asgiref.sync import sync_to_async
from django.contrib import auth
from django.contrib.auth.backends import ModelBackend
from django.contrib.auth.base_user import AbstractBaseUser
from django.contrib.auth.hashers import make_password
from django.core.exceptions import PermissionDenied
from django.http import HttpRequest
from django.views.decorators.debug import sensitive_variables

from . import utils
from .models import FailedAuthenticationAttempt


@sensitive_variables()
def hash_password(credentials: dict[str, object]) -> None:
    password = credentials.get("password")
    if isinstance(password, str):
        make_password(password)


@sensitive_variables()
def gate(request: HttpRequest | None, credentials: dict[str, object]) -> None:
    bucket = utils.get_bucket(request, credentials)
    utils.stash_bucket(request, credentials, bucket)
    if bucket and FailedAuthenticationAttempt.objects.is_locked_out(*bucket):
        hash_password(credentials)
        raise PermissionDenied


class DeviceCookieBackend:
    @sensitive_variables("credentials")
    def authenticate(self, request: HttpRequest | None, **credentials: object) -> None:
        gate(request, credentials)

    @sensitive_variables("credentials")
    async def aauthenticate(
        self, request: HttpRequest | None, **credentials: object
    ) -> None:
        await sync_to_async(gate)(request, credentials)

    def get_user(self, user_id: object) -> AbstractBaseUser | None:
        for backend in auth.get_backends():
            if isinstance(backend, DeviceCookieBackend):
                continue
            user = backend.get_user(user_id)
            if user is not None:
                return user
        return None

    async def aget_user(self, user_id: object) -> AbstractBaseUser | None:
        return await sync_to_async(self.get_user)(user_id)


class DeviceCookieModelBackend(ModelBackend):
    @sensitive_variables("credentials")
    def authenticate(
        self, request: HttpRequest | None, **credentials: object
    ) -> AbstractBaseUser | None:
        gate(request, credentials)
        return super().authenticate(request, **credentials)

    @sensitive_variables("credentials")
    async def aauthenticate(
        self, request: HttpRequest | None, **credentials: object
    ) -> AbstractBaseUser | None:
        return await sync_to_async(self.authenticate)(request, **credentials)
