from django.contrib.auth import signals as auth_signals
from django.dispatch import receiver

from . import config
from .models import FailedAuthenticationAttempt
from .models import Lockout


@receiver(auth_signals.user_logged_in)
def set_device_cookie(sender, request, user, **kwargs):
    request.issue_device_cookie = True


@receiver(auth_signals.user_login_failed)
def check_for_lockout(sender, credentials, request, **kwargs):
    device_cookie = request.COOKIES.get(config.DEVICE_COOKIE_NAME, "")
    FailedAuthenticationAttempt.objects.register_failure(
        credentials["username"], device_cookie
    )
    if FailedAuthenticationAttempt.objects.should_lock_out_user(
        credentials["username"], device_cookie
    ):
        Lockout.objects.lock_out_user(credentials["username"], device_cookie)
