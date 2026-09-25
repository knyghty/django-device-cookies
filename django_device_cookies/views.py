from django.contrib.auth import views as auth_views
from django.http import HttpRequest
from django.http import HttpResponse
from django.urls import URLPattern
from django.urls import URLResolver
from django.urls import get_resolver
from django.urls import get_urlconf
from django.utils.translation import gettext_lazy

from . import utils

LOCKOUT_MESSAGE = gettext_lazy("Too many failed attempts. Try again later.")
LOCKOUT_MESSAGE_WITH_RESET = gettext_lazy(
    "Too many failed attempts. Try again later, or request a password reset and "
    "open the link in this browser. You do not need to change your password."
)


class PasswordResetConfirmView(auth_views.PasswordResetConfirmView):
    def get(
        self, request: HttpRequest, *args: object, **kwargs: object
    ) -> HttpResponse:
        token = self.request.session[auth_views.INTERNAL_RESET_SESSION_TOKEN]
        nonce = utils.derive_nonce(token)
        utils.trust_device(request, self.user, nonce)
        return super().get(request, *args, **kwargs)


def routes_reset_view(pattern: URLPattern | URLResolver) -> bool:
    if isinstance(pattern, URLResolver):
        return any(map(routes_reset_view, pattern.url_patterns))
    view_class = getattr(pattern.callback, "view_class", object)
    return issubclass(view_class, PasswordResetConfirmView)


def get_lockout_message() -> str:
    patterns = get_resolver(get_urlconf()).url_patterns
    if any(map(routes_reset_view, patterns)):
        return LOCKOUT_MESSAGE_WITH_RESET
    return LOCKOUT_MESSAGE
