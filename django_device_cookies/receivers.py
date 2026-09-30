import logging

from django.contrib.auth import signals as auth_signals
from django.contrib.auth.base_user import AbstractBaseUser
from django.dispatch import receiver
from django.http import HttpRequest

from . import utils
from .models import FailedAuthenticationAttempt
from .signals import lockout

logger = logging.getLogger("django_device_cookies")


@receiver(auth_signals.user_logged_in, dispatch_uid="django_device_cookies.login")
def remember_login(
    sender: object,
    user: AbstractBaseUser,
    request: HttpRequest | None = None,
    **kwargs: object,
) -> None:
    if request is not None:
        utils.trust_device(request, user)


@receiver(auth_signals.user_login_failed, dispatch_uid="django_device_cookies.failure")
def record_failure(
    sender: object,
    credentials: dict[str, object],
    request: HttpRequest | None = None,
    **kwargs: object,
) -> None:
    bucket = utils.pop_bucket(request, credentials)
    if bucket is None:
        return
    attempts = FailedAuthenticationAttempt.objects
    if attempts.record_failure(bucket):
        clients = "device" if bucket.device else "untrusted clients"
        logger.warning("Locked out %s for username %r.", clients, bucket.username)
        lockout.send(
            sender=FailedAuthenticationAttempt,
            username=bucket.username,
            device=bucket.device,
            request=request,
        )
    if bucket.device and attempts.is_revoked(bucket):
        logger.warning("Revoked a device of username %r.", bucket.username)
