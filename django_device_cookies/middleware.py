from . import utils


class DeviceCookieMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        response = self.get_response(request)
        if hasattr(request, "issue_device_cookie"):
            utils.issue_device_cookie(response, request.user)
        return response
