from django.contrib import admin
from django.contrib.auth import authenticate
from django.contrib.auth import login
from django.contrib.auth import logout
from django.contrib.auth import views as auth_views
from django.http import HttpRequest
from django.http import HttpResponse
from django.urls import path
from django.views.decorators.csrf import csrf_exempt

from django_device_cookies.views import PasswordResetConfirmView


class Wrapped:
    def __init__(self, request: HttpRequest) -> None:
        self._request = request

    def __getattr__(self, name: str) -> object:
        return getattr(self._request, name)


@csrf_exempt
def login_wrapped(request: HttpRequest) -> HttpResponse:
    wrapped = Wrapped(request)
    user = authenticate(
        wrapped, username=request.POST["username"], password=request.POST["password"]
    )
    login(wrapped, user)
    return HttpResponse()


def explode(request: HttpRequest) -> HttpResponse:
    raise RuntimeError


@csrf_exempt
def login_logout(request: HttpRequest) -> HttpResponse:
    user = authenticate(
        request, username=request.POST["username"], password=request.POST["password"]
    )
    login(request, user)
    logout(request)
    return HttpResponse()


urlpatterns = [
    path("admin/", admin.site.urls),
    path("login/", auth_views.LoginView.as_view(), name="login"),
    path("login-logout/", login_logout, name="login-logout"),
    path("login-wrapped/", login_wrapped, name="login-wrapped"),
    path("explode/", explode, name="explode"),
    path(
        "reset/<uidb64>/<token>/",
        PasswordResetConfirmView.as_view(),
        name="password_reset_confirm",
    ),
    path(
        "reset/done/",
        auth_views.PasswordResetCompleteView.as_view(),
        name="password_reset_complete",
    ),
]
