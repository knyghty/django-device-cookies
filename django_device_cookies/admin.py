from django.contrib import admin

from .models import FailedAuthenticationAttempt
from .models import Lockout


@admin.register(FailedAuthenticationAttempt)
class FailedAuthenticationAttemptAdmin(admin.ModelAdmin):
    list_display = ["user", "time", "device_cookie"]


@admin.register(Lockout)
class LockoutAdmin(admin.ModelAdmin):
    list_display = ["user", "expiry", "device_cookie"]
