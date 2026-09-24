=====================
Django Device Cookies
=====================

Throttle login attempts with `device cookies`_. Each login sets a signed
cookie, and failed attempts count per cookie, or per username for requests
without a valid one.

Why
---

Temporary account lockout after several failed attempts is an easy target for
denial of service: a fixed lockout policy lets an attacker lock selected users
out of the site. Locking the account/IP pair instead is better against denial
of service but weaker against botnets and proxies, and harder to implement
correctly. Device cookies are a variant of account/IP blocking that uses a
browser cookie instead of an IP address. Clients that have previously logged
in are trusted and locked out individually. All untrusted clients share one
temporary lockout per account, which bounds the guesses against an account to
``DEVICE_COOKIE_ATTEMPTS_PER_PERIOD`` per ``DEVICE_COOKIE_PERIOD`` regardless
of the size of the botnet.

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

- Only calls to ``authenticate()`` and ``aauthenticate()`` are throttled. Calls
  without a request count as untrusted.
- Attempts sent in parallel can exceed the limit.
- If Django masks your ``USERNAME_FIELD`` in the ``user_login_failed`` signal,
  calls that pass it by name are not throttled.

.. _`device cookies`: https://owasp.org/www-community/Slow_Down_Online_Guessing_Attacks_with_Device_Cookies
