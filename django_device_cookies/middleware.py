from http import HTTPStatus

from django.http import HttpRequest
from django.http import HttpResponse
from django.http import HttpResponseBase
from django.utils.deprecation import MiddlewareMixin

from . import utils


class DeviceCookieMiddleware(MiddlewareMixin):
    def process_response(
        self, request: HttpRequest, response: HttpResponseBase
    ) -> HttpResponseBase:
        payload = request.META.get(utils.META_KEY)
        if payload is not None:
            utils.issue_device_cookie(response, payload)
        return response

    def process_exception(
        self, request: HttpRequest, exception: Exception
    ) -> HttpResponse | None:
        if not isinstance(exception, utils.LockedOutError):
            return None
        return HttpResponse(
            exception.messages[0],
            status=HTTPStatus.TOO_MANY_REQUESTS,
            content_type="text/plain; charset=utf-8",
        )

    async def __acall__(self, request: HttpRequest) -> HttpResponseBase:
        return self.process_response(request, await self.get_response(request))
