from django.http import HttpRequest
from django.http import HttpResponseBase
from django.utils.deprecation import MiddlewareMixin

from . import utils


class DeviceCookieMiddleware(MiddlewareMixin):
    def process_response(
        self, request: HttpRequest, response: HttpResponseBase
    ) -> HttpResponseBase:
        trusted = request.META.get(utils.META_KEY)
        if trusted is not None:
            utils.issue_device_cookie(response, *trusted)
        return response

    async def __acall__(self, request: HttpRequest) -> HttpResponseBase:
        return self.process_response(request, await self.get_response(request))
