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
browser cookie instead of an IP address. The throttle trusts a client that
logged in before and locks it out individually. All untrusted clients share
one temporary lockout per account. That bounds the guesses against an account
to ``DEVICE_COOKIE_ATTEMPTS_PER_PERIOD`` per ``DEVICE_COOKIE_PERIOD``
regardless of the size of the botnet.

Installation
------------

1. Add ``"django_device_cookies"`` to ``INSTALLED_APPS``.
2. Add ``"django_device_cookies.middleware.DeviceCookieMiddleware"`` to
   ``MIDDLEWARE``.
3. Put ``"django_device_cookies.backends.DeviceCookieBackend"`` first in
   ``AUTHENTICATION_BACKENDS``, before ``ModelBackend`` or your own backends.
4. Run ``manage.py migrate``.

With two backends, a call to ``login()`` for a user that did not come from
``authenticate()`` must pass ``backend``, as the Django documentation says.

``django_device_cookies.backends.DeviceCookieModelBackend`` is ``ModelBackend``
with the throttle built in, for projects that want a single entry. Django
stores the path of the backend that authenticated a user in the session.
Replacing ``ModelBackend`` with it logs out every existing session.

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
    DEVICE_COOKIE_HIDE_LOCKOUTS = False

``DEVICE_COOKIE_PER_USER`` sets one cookie per user instead of per browser.
``DEVICE_COOKIE_REVOKE_AFTER_FAILURES`` stops trusting a cookie after that many
failures over its life. ``DEVICE_COOKIE_HIDE_LOCKOUTS`` makes a locked-out
attempt fail exactly like a wrong password: the login form shows its usual
error, and the response takes the same password hashing time.

Lockouts
--------

A locked-out attempt raises
``django_device_cookies.exceptions.LockedOutError``, a ``ValidationError`` with
the code ``locked_out``. Every login form built on
``authenticate()`` shows its message: "Too many failed attempts. Try again
later." If your URLs route the password reset view below, the message also
tells the user to open a reset link in the same browser. Code that calls
``authenticate()`` outside a form gets a 429 response with the message from
the middleware.

The message is a form error. A template that prints its own sentence instead
of the form's errors, as the login template in the Django documentation does,
never shows it.

Password reset
--------------

An attacker can keep the untrusted lockout for an account in place, which
blocks its user from logging in from a new device. OWASP suggests issuing a
device cookie when the user visits a password reset link, since that proves
possession of the email account. An actual password reset is not necessary.
``django_device_cookies.views.PasswordResetConfirmView`` does this. Add it to
your URLs before ``include("django.contrib.auth.urls")``:

.. code-block:: python

    from django_device_cookies.views import PasswordResetConfirmView

    path(
        "accounts/reset/<uidb64>/<token>/",
        PasswordResetConfirmView.as_view(),
        name="password_reset_confirm",
    ),

It renders ``registration/password_reset_confirm.html``, like Django's view.

Signals
-------

``django_device_cookies.signals.lockout``
    Sent when an account or a device reaches the failed attempt limit.

    Arguments sent with this signal:

    ``sender``
        The ``FailedAuthenticationAttempt`` class.

    ``username``
        The normalized username.

    ``device``
        The device cookie nonce, or ``""`` for untrusted clients.

    ``request``
        The current ``HttpRequest``, or ``None``.

Maintenance
-----------

Nothing removes expired failed attempts automatically. The
``clear_device_cookie_attempts`` management command deletes them. Run it on a
regular basis, for example as a daily cron job.

Limitations
-----------

- The throttle covers only calls to ``authenticate()`` and
  ``aauthenticate()``. Calls without a request count as untrusted.
- Attempts sent in parallel can exceed the limit.
- If Django masks your ``USERNAME_FIELD`` in the ``user_login_failed`` signal,
  the throttle ignores calls without a request that pass it by name.

System checks
-------------

* **device_cookies.E001**: ``AUTHENTICATION_BACKENDS`` has no device cookie
  backend. Nothing throttles logins.
* **device_cookies.W001**: The device cookie backend is not first in
  ``AUTHENTICATION_BACKENDS``. A locked-out client that knows the password
  still logs in.
* **device_cookies.E002**: ``MIDDLEWARE`` has no device cookie middleware. No
  client gets a device cookie, and every login attempt counts as untrusted.
* **device_cookies.E003**: ``<setting>`` must be ``<expected>``.
* **device_cookies.E004**: Browsers reject a ``SameSite=None`` cookie that is
  not ``Secure``. No client gets a device cookie.
* **device_cookies.E005**: ``AUTHENTICATION_BACKENDS`` has only the device
  cookie backend. Nothing authenticates.
* **device_cookies.W003**: Django masks ``USERNAME_FIELD`` ``<field>`` in the
  ``user_login_failed`` signal. The throttle ignores calls to
  ``authenticate()`` without a request that pass it by name.

This check runs only with the ``--deploy`` option:

* **device_cookies.W002**: ``DEVICE_COOKIE_SECURE`` is off. Browsers send
  device cookies over HTTP.

.. _`device cookies`: https://owasp.org/www-community/Slow_Down_Online_Guessing_Attacks_with_Device_Cookies
