import datetime

from django.conf import settings

DEVICE_COOKIE_NAME = getattr(settings, "DEVICE_COOKIE_NAME", "django_device")

DEVICE_COOKIE_PERIOD = getattr(
    settings, "DEVICE_COOKIES_PERIOD", datetime.timedelta(hours=1)
)

DEVICE_COOKIE_REQUESTS_PER_PERIOD = getattr(
    settings, "DEVICE_COOKIES_REQUESTS_PER_PERIOD", 3
)

DEVICE_COOKIE_SAMESITE = getattr(settings, "DEVICE_COOKIE_SAMESITE", "Lax")

DEVICE_COOKIE_SECURE = getattr(settings, "DEVICE_COOKIE_SECURE", True)
