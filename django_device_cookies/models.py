import datetime
import hashlib
import unicodedata
from typing import NamedTuple

from django.conf import settings
from django.contrib.auth.base_user import AbstractBaseUser
from django.db import models
from django.db.models.functions import Now

from . import config

KEY_LENGTH = 64
NONCE_LENGTH = 32


def normalize_username(username: object) -> str:
    return unicodedata.normalize("NFKC", str(username)).casefold()


def hash_username(username: str) -> str:
    return hashlib.sha256(username.encode()).hexdigest()


def get_cutoff(age: datetime.timedelta) -> models.Expression:
    return Now() - models.Value(age, output_field=models.DurationField())


class Bucket(NamedTuple):
    identifier: str
    device: str
    user: AbstractBaseUser | None = None

    @property
    def username(self) -> str:
        if self.user is None:
            return self.identifier
        return normalize_username(self.user.get_username())


class FailedAuthenticationAttemptQuerySet(models.QuerySet):
    def filter_bucket(self, bucket: Bucket) -> "FailedAuthenticationAttemptQuerySet":
        return self.filter(key=hash_username(bucket.username), device=bucket.device)

    def filter_recent(self, bucket: Bucket) -> "FailedAuthenticationAttemptQuerySet":
        cutoff = get_cutoff(config.DEVICE_COOKIE_PERIOD)
        return self.filter_bucket(bucket).filter(time__gt=cutoff)

    def filter_identifier(
        self, bucket: Bucket
    ) -> "FailedAuthenticationAttemptQuerySet":
        identifier = hash_username(bucket.identifier)
        return self.filter_recent(bucket).filter(identifier=identifier)

    def filter_stale(self) -> "FailedAuthenticationAttemptQuerySet":
        stale = models.Q(time__lte=get_cutoff(config.DEVICE_COOKIE_PERIOD))
        if config.DEVICE_COOKIE_REVOKE_AFTER_FAILURES:
            expired = get_cutoff(config.DEVICE_COOKIE_MAX_AGE)
            stale = (stale & models.Q(device="")) | models.Q(time__lte=expired)
        return self.filter(stale)

    def is_locked_out(self, bucket: Bucket) -> bool:
        count = self.filter_recent(bucket).count()
        return count >= config.DEVICE_COOKIE_ATTEMPTS_PER_PERIOD

    def is_identifier_locked_out(self, bucket: Bucket) -> bool:
        count = self.filter_identifier(bucket).count()
        return count >= config.DEVICE_COOKIE_ATTEMPTS_PER_PERIOD

    def is_revoked(self, bucket: Bucket) -> bool:
        limit = config.DEVICE_COOKIE_REVOKE_AFTER_FAILURES
        if not limit:
            return False
        return self.filter_bucket(bucket).count() >= limit

    def record_failure(self, bucket: Bucket) -> bool:
        identifier = hash_username(bucket.identifier)
        recent = self.filter_recent(bucket).values_list("identifier", flat=True)
        identifiers = list(recent)
        limit = config.DEVICE_COOKIE_ATTEMPTS_PER_PERIOD
        if identifiers.count(identifier) >= limit:
            return False
        self.create(
            key=hash_username(bucket.username),
            identifier=identifier,
            device=bucket.device,
            user=bucket.user,
        )
        return len(identifiers) + 1 == limit


class FailedAuthenticationAttempt(models.Model):
    key = models.CharField(max_length=KEY_LENGTH)
    identifier = models.CharField(max_length=KEY_LENGTH)
    device = models.CharField(max_length=NONCE_LENGTH, blank=True)
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="+",
    )
    time = models.DateTimeField(db_default=Now())

    objects = models.Manager.from_queryset(FailedAuthenticationAttemptQuerySet)()

    class Meta:
        indexes = [models.Index(fields=["key", "device", "time"])]

    def __str__(self) -> str:
        owner = self.user or self.key
        return f"{owner} ({self.device or 'untrusted'}) at {self.time}"
