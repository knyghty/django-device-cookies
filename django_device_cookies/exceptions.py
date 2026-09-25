from django.core.exceptions import ValidationError


class LockedOutError(ValidationError):
    pass
