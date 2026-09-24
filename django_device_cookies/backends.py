from asgiref.sync import sync_to_async
from django.contrib.auth import get_user_model
from django.contrib.auth.backends import ModelBackend
from django.contrib.auth.base_user import AbstractBaseUser
from django.core.exceptions import PermissionDenied
from django.http import HttpRequest
from django.views.decorators.debug import sensitive_variables

from . import utils
from .models import FailedAuthenticationAttempt


def gate(request: HttpRequest | None, credentials: dict[str, object]) -> None:
    bucket = utils.get_bucket(request, credentials)
    if bucket and FailedAuthenticationAttempt.objects.is_locked_out(*bucket):
        password = credentials.get("password")
        if isinstance(password, str):
            get_user_model()().set_password(password)
        raise PermissionDenied


class DeviceCookieBackend:
    @sensitive_variables("credentials")
    def authenticate(self, request: HttpRequest | None, **credentials: object) -> None:
        gate(request, credentials)

    @sensitive_variables("credentials")
    async def aauthenticate(
        self, request: HttpRequest | None, **credentials: object
    ) -> None:
        return await sync_to_async(self.authenticate)(request, **credentials)


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
        await sync_to_async(gate)(request, credentials)
        return await super().aauthenticate(request, **credentials)
