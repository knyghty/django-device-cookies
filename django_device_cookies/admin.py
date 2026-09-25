from collections.abc import Sequence

from django.contrib import admin
from django.contrib.auth import get_user_model
from django.db.models import QuerySet
from django.http import HttpRequest

from . import utils
from .models import FailedAuthenticationAttempt
from .models import hash_username

SEARCH_PREFIXES = "^=@"


def prefix_user_field(field: str) -> str:
    if field[0] in SEARCH_PREFIXES:
        return f"{field[0]}user__{field[1:]}"
    return f"user__{field}"


@admin.register(FailedAuthenticationAttempt)
class FailedAuthenticationAttemptAdmin(admin.ModelAdmin):
    list_display = ["user", "key", "device", "time"]
    list_select_related = ["user"]
    ordering = ["-time"]

    @property
    def search_help_text(self) -> str:
        user_model = get_user_model()
        field = user_model._meta.get_field(user_model.USERNAME_FIELD)
        return (
            f"Search the users, or enter the exact {field.verbose_name} "
            "for attempts without one."
        )

    def get_search_fields(self, request: HttpRequest) -> Sequence[str]:
        user_model = get_user_model()
        user_admin = self.admin_site._registry.get(user_model)
        if user_admin is None:
            return [f"user__{user_model.USERNAME_FIELD}"]
        return [prefix_user_field(f) for f in user_admin.get_search_fields(request)]

    def get_search_results(
        self, request: HttpRequest, queryset: QuerySet, search_term: str
    ) -> tuple[QuerySet, bool]:
        matches, duplicates = super().get_search_results(request, queryset, search_term)
        if search_term:
            key = hash_username(utils.normalize_username(search_term))
            matches |= queryset.filter(key=key)
        return matches, duplicates
