from django.contrib import admin
from django.contrib.auth import get_user_model
from django.db.models import QuerySet
from django.http import HttpRequest

from . import utils
from .models import FailedAuthenticationAttempt


@admin.register(FailedAuthenticationAttempt)
class FailedAuthenticationAttemptAdmin(admin.ModelAdmin):
    list_display = ["username", "device", "time"]
    ordering = ["-time"]
    search_fields = ["username__startswith"]

    @property
    def search_help_text(self) -> str:
        user_model = get_user_model()
        field = user_model._meta.get_field(user_model.USERNAME_FIELD)
        return f"Enter the start of the {field.verbose_name}."

    def get_search_results(
        self, request: HttpRequest, queryset: QuerySet, search_term: str
    ) -> tuple[QuerySet, bool]:
        return super().get_search_results(
            request, queryset, utils.normalize_username(search_term)
        )
