from django.contrib.auth import views as auth_views
from django.http import HttpRequest
from django.http import HttpResponse

from . import utils


class PasswordResetConfirmView(auth_views.PasswordResetConfirmView):
    """Derive the nonce from the token, so one link stays one device when reopened."""

    def get(
        self, request: HttpRequest, *args: object, **kwargs: object
    ) -> HttpResponse:
        token = self.request.session[auth_views.INTERNAL_RESET_SESSION_TOKEN]
        nonce = utils.derive_nonce(token)
        utils.trust_device(request, self.user.get_username(), nonce)
        return super().get(request, *args, **kwargs)
