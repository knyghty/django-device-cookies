from django.conf import settings
from django.contrib.auth import get_user_model
from django.db import models
from django.db.models.functions import Now

from . import config


class FailedAuthenticationAttemptQuerySet(models.QuerySet):
    def register_failure(self, username, device_cookie):
        username_field = get_user_model().USERNAME_FIELD
        user = get_user_model().objects.get(**{username_field: username})
        self.create(user=user, device_cookie=device_cookie)

    def should_lock_out_user(self, username, device_cookie):
        username_field = get_user_model().USERNAME_FIELD
        filters = {
            f"user__{username_field}": username,
            "device_cookie": device_cookie,
            "time__gt": Now() - config.DEVICE_COOKIE_PERIOD,
        }
        return (
            self.filter(**filters).count() >= config.DEVICE_COOKIE_REQUESTS_PER_PERIOD
        )


class LockoutQuerySet(models.QuerySet):
    def is_user_locked_out(self, username, device_cookie):
        username_field = get_user_model().USERNAME_FIELD
        filters = {
            f"user__{username_field}": username,
            "device_cookie": device_cookie,
            "expiry__lt": Now() + config.DEVICE_COOKIE_PERIOD,
        }
        return self.filter(**filters).exists()

    def lock_out_user(self, username, device_cookie):
        username_field = get_user_model().USERNAME_FIELD
        user = get_user_model().objects.get(**{username_field: username})
        expiry = Now() + config.DEVICE_COOKIE_PERIOD
        self.create(user=user, expiry=expiry, device_cookie=device_cookie)


class FailedAuthenticationAttempt(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    time = models.DateTimeField(db_default=Now())
    device_cookie = models.TextField(blank=True)

    objects = FailedAuthenticationAttemptQuerySet.as_manager()

    def __str__(self):
        return f"{self.user}/{self.device_cookie} at {self.time}"


class Lockout(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    expiry = models.DateTimeField()
    device_cookie = models.TextField(blank=True)

    objects = LockoutQuerySet.as_manager()

    def __str__(self):
        return f"{self.user}/{self.device_cookie} until {self.expiry}"
