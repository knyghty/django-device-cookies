from django.contrib import admin

from .models import FailedAuthenticationAttempt


@admin.register(FailedAuthenticationAttempt)
class FailedAuthenticationAttemptAdmin(admin.ModelAdmin):
    list_display = ["username", "device", "time"]
    ordering = ["-time"]
    search_fields = ["username"]
