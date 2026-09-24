=====================
Django Device Cookies
=====================

Throttle login attempts with `device cookies`_. Each login sets a signed
cookie, and failed attempts count per cookie, or per username for requests
without a valid one. After the limit, the backend rejects attempts like wrong
passwords. That locks out an attacker, but not the owner's known browsers.

Installation
------------

1. Add ``"django_device_cookies"`` to ``INSTALLED_APPS``.
2. Add ``"django_device_cookies.middleware.DeviceCookieMiddleware"`` to
   ``MIDDLEWARE``.
3. Set ``AUTHENTICATION_BACKENDS`` to
   ``["django_device_cookies.backends.DeviceCookieModelBackend"]``.
4. Run ``migrate``.

If your project uses other backends, put
``"django_device_cookies.backends.DeviceCookieBackend"`` first instead. System
checks report mistakes.

Settings
--------

The defaults:

.. code-block:: python

    DEVICE_COOKIE_NAME = "django_device"
    DEVICE_COOKIE_PERIOD = timedelta(minutes=15)
    DEVICE_COOKIE_ATTEMPTS_PER_PERIOD = 5
    DEVICE_COOKIE_MAX_AGE = timedelta(days=365)
    DEVICE_COOKIE_SECURE = True
    DEVICE_COOKIE_SAMESITE = "Lax"
    DEVICE_COOKIE_DOMAIN = None
    DEVICE_COOKIE_PATH = "/"
    DEVICE_COOKIE_PER_USER = False
    DEVICE_COOKIE_REVOKE_AFTER_FAILURES = None

``DEVICE_COOKIE_PER_USER`` sets one cookie per user instead of per browser.
``DEVICE_COOKIE_REVOKE_AFTER_FAILURES`` stops trusting a cookie after that many
failures over its life.

Password reset
--------------

A valid password reset link gives a locked-out owner a device cookie. Route
``django_device_cookies.views.PasswordResetConfirmView`` before
``include("django.contrib.auth.urls")``:

.. code-block:: python

    from django_device_cookies.views import PasswordResetConfirmView

    path(
        "accounts/reset/<uidb64>/<token>/",
        PasswordResetConfirmView.as_view(),
        name="password_reset_confirm",
    ),

It renders ``registration/password_reset_confirm.html``, like Django's view.

Operation
---------

Each lockout logs a warning and sends
``django_device_cookies.signals.lockout``. Run
``manage.py clear_device_cookie_attempts`` on a schedule. To lift a lockout,
delete the user's attempts in the admin.

Limitations
-----------

- The throttle sees only calls to ``authenticate()`` with a request.
- A client with a cookie can drop it, so it gets two buckets.
- Requests that arrive at the same moment can all pass the gate.
- One password tried against many accounts is not throttled.
- The database keeps every submitted username in plain text.
- Every ``login()`` call sets a cookie, including staff impersonation.
- Django masks a ``USERNAME_FIELD`` that contains ``api``, ``token``, ``key``,
  ``secret``, ``password`` or ``signature``. The throttle ignores callers that
  pass such a field by name. A system check warns.

.. _`device cookies`: https://owasp.org/www-community/Slow_Down_Online_Guessing_Attacks_with_Device_Cookies
