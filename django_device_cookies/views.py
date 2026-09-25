import functools
from collections.abc import Iterable

from django.contrib.auth import views as auth_views
from django.http import HttpRequest
from django.http import HttpResponse
from django.urls import URLResolver

from . import utils


class PasswordResetConfirmView(auth_views.PasswordResetConfirmView):
    def get(
        self, request: HttpRequest, *args: object, **kwargs: object
    ) -> HttpResponse:
        token = self.request.session[auth_views.INTERNAL_RESET_SESSION_TOKEN]
        nonce = utils.derive_nonce(token)
        utils.trust_device(request, self.user, nonce)
        return super().get(request, *args, **kwargs)


def find_reset_view(patterns: Iterable[object]) -> bool:
    for pattern in patterns:
        if isinstance(pattern, URLResolver):
            if find_reset_view(pattern.url_patterns):
                return True
            continue
        view_class = getattr(getattr(pattern, "callback", None), "view_class", None)
        if isinstance(view_class, type) and issubclass(
            view_class, PasswordResetConfirmView
        ):
            return True
    return False


@functools.cache
def has_reset_view(resolver: URLResolver) -> bool:
    return find_reset_view(resolver.url_patterns)
