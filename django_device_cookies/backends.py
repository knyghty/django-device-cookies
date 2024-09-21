from django.contrib.auth.backends import BaseBackend
from django.core.exceptions import PermissionDenied

from . import config
from . import utils
from .models import Lockout


class DeviceCookieBackend(BaseBackend):
    def authenticate(self, request, username=None, **kwargs):
        if username is None:
            # Only username based authentication is supported.
            return None
        if cookie := request.COOKIES.get(config.DEVICE_COOKIE_NAME, ""):
            if not utils.validate_device_cookie(cookie, username):
                if Lockout.objects.is_user_locked_out(
                    username=username, device_cookie=cookie
                ):
                    raise PermissionDenied
        if Lockout.objects.is_user_locked_out(username=username, device_cookie=""):
            raise PermissionDenied
        return None
