import datetime
import hashlib

from django.db import models
from django.utils import timezone

from . import config

KEY_LENGTH = 64
NONCE_LENGTH = 32


def hash_username(username: str) -> str:
    return hashlib.sha256(username.encode()).hexdigest()


def get_cutoff() -> datetime.datetime:
    return timezone.now() - config.DEVICE_COOKIE_PERIOD


class FailedAuthenticationAttemptQuerySet(models.QuerySet):
    def filter_bucket(
        self, username: str, device: str
    ) -> "FailedAuthenticationAttemptQuerySet":
        return self.filter(key=hash_username(username), device=device)

    def filter_recent(
        self, username: str, device: str
    ) -> "FailedAuthenticationAttemptQuerySet":
        return self.filter_bucket(username, device).filter(time__gt=get_cutoff())

    def filter_stale(self) -> "FailedAuthenticationAttemptQuerySet":
        stale = models.Q(time__lte=get_cutoff())
        if config.DEVICE_COOKIE_REVOKE_AFTER_FAILURES:
            expired = timezone.now() - config.DEVICE_COOKIE_MAX_AGE
            stale = (stale & models.Q(device="")) | models.Q(time__lte=expired)
        return self.filter(stale)

    def is_locked_out(self, username: str, device: str) -> bool:
        count = self.filter_recent(username, device).count()
        return count >= config.DEVICE_COOKIE_ATTEMPTS_PER_PERIOD

    def is_revoked(self, username: str, device: str) -> bool:
        limit = config.DEVICE_COOKIE_REVOKE_AFTER_FAILURES
        if not limit:
            return False
        return self.filter_bucket(username, device).count() >= limit

    def record_failure(self, username: str, device: str) -> bool:
        if self.is_locked_out(username, device):
            return False
        self.create(key=hash_username(username), device=device)
        return self.is_locked_out(username, device)


class FailedAuthenticationAttempt(models.Model):
    key = models.CharField(max_length=KEY_LENGTH)
    device = models.CharField(max_length=NONCE_LENGTH, blank=True)
    time = models.DateTimeField(default=timezone.now)

    objects = models.Manager.from_queryset(FailedAuthenticationAttemptQuerySet)()

    class Meta:
        indexes = [models.Index(fields=["key", "device", "time"])]

    def __str__(self) -> str:
        return f"{self.key} ({self.device or 'untrusted'}) at {self.time}"
