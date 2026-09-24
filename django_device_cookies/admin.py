from django.contrib import admin
from django.contrib.auth import get_user_model
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

    @property
    def search_help_text(self) -> str:
        user_model = get_user_model()
        field = user_model._meta.get_field(user_model.USERNAME_FIELD)
        return f"Enter the {field.verbose_name} or a key."

    def get_search_results(
        self, request: HttpRequest, queryset: QuerySet, search_term: str
    ) -> tuple[QuerySet, bool]:
        if search_term:
            key = hash_username(utils.normalize_username(search_term))
            queryset = queryset.filter(Q(key=key) | Q(key=search_term))
        return queryset, False
