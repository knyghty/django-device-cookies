from typing import TYPE_CHECKING
from typing import cast

from allauth.account import views as allauth_views
from django.forms import Form
from django.http import HttpRequest
from django.http import HttpResponse

from . import utils
from .views import IssuesDeviceCookie

if TYPE_CHECKING:
    from allauth.account.internal.flows.password_reset_by_code import (
        PasswordResetVerificationProcess,
    )
    from django.contrib.auth.base_user import AbstractBaseUser


class PasswordResetFromKeyView(
    IssuesDeviceCookie, allauth_views.PasswordResetFromKeyView
):
    def get(
        self, request: HttpRequest, *args: object, **kwargs: object
    ) -> HttpResponse:
        user = cast("AbstractBaseUser", self.reset_user)
        utils.trust_device(request, user, utils.derive_nonce(self.key))
        return super().get(request, *args, **kwargs)


class ConfirmPasswordResetCodeView(
    IssuesDeviceCookie, allauth_views.ConfirmPasswordResetCodeView
):
    def form_valid(self, form: Form) -> HttpResponse:
        process = cast("PasswordResetVerificationProcess", self._process)
        utils.trust_device(self.request, cast("AbstractBaseUser", process.user))
        return super().form_valid(form)
