from django.contrib import admin
from django.db.models import Q
from django.db.models import QuerySet
from django.http import HttpRequest

from . import utils
from .models import FailedAuthenticationAttempt
from .models import hash_username


@admin.register(FailedAuthenticationAttempt)
class FailedAuthenticationAttemptAdmin(admin.ModelAdmin):
    list_display = ["key", "device", "time"]
    ordering = ["-time"]
    search_fields = ["key"]
    search_help_text = "Enter a username or a key."

    def get_search_results(
        self, request: HttpRequest, queryset: QuerySet, search_term: str
    ) -> tuple[QuerySet, bool]:
        if search_term:
            key = hash_username(utils.normalize_username(search_term))
            queryset = queryset.filter(Q(key=key) | Q(key=search_term))
        return queryset, False
