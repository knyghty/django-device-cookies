from django.contrib.auth import views as auth_views
from django.urls import include
from django.urls import path

from django_device_cookies.views import PasswordResetConfirmView

reset = [
    path(
        "<uidb64>/<token>/",
        PasswordResetConfirmView.as_view(),
        name="password_reset_confirm",
    ),
]

urlpatterns = [
    path("login/", auth_views.LoginView.as_view(), name="login"),
    path("reset/", include((reset, "accounts"))),
]
