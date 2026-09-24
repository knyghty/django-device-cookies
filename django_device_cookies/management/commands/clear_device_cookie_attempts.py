from django.core.management.base import BaseCommand
from django.template.defaultfilters import pluralize

from django_device_cookies.models import FailedAuthenticationAttempt


class Command(BaseCommand):
    help = "Delete failed authentication attempts too old to count towards a lockout."

    def handle(self, *args: object, **options: object) -> None:
        deleted, _ = FailedAuthenticationAttempt.objects.filter_stale().delete()
        if options["verbosity"]:
            noun = f"attempt{pluralize(deleted)}"
            self.stdout.write(f"Deleted {deleted} failed authentication {noun}.")
