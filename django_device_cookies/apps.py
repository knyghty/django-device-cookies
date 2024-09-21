from django.apps import AppConfig


class DeviceCookiesConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "django_device_cookies"
    label = "device_cookies"

    def ready(self):
        from . import signals
