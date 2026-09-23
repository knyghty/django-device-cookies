from pathlib import Path

AUTHENTICATION_BACKENDS = [
    "django_device_cookies.backends.DeviceCookieBackend",
    "django.contrib.auth.backends.ModelBackend",
]

DATABASES = {"default": {"ENGINE": "django.db.backends.sqlite3", "NAME": ":memory:"}}

DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"

INSTALLED_APPS = [
    "django_device_cookies",
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.messages",
    "django.contrib.sessions",
]

MIDDLEWARE = [
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django_device_cookies.middleware.DeviceCookieMiddleware",
]

PASSWORD_HASHERS = ["django.contrib.auth.hashers.MD5PasswordHasher"]

ROOT_URLCONF = "tests.urls"

SECRET_KEY = "django-insecure-dummy"

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [Path(__file__).parent / "templates"],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
                "django.template.context_processors.request",
            ]
        },
    }
]
