import secrets

from django.core import signing

from . import config

signer = signing.Signer()


def issue_device_cookie(response, user):
    nonce = secrets.token_hex()
    value = signer.sign_object((user.get_username(), nonce))
    response.set_cookie(
        config.DEVICE_COOKIE_NAME,
        value,
        httponly=True,
        secure=config.DEVICE_COOKIE_SECURE,
        samesite=config.DEVICE_COOKIE_SAMESITE,
    )


def validate_device_cookie(cookie, username):
    try:
        return signer.unsign_object(cookie)[0] == username
    except signing.BadSignature:
        return False
