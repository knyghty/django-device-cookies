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

``DEVICE_COOKIE_NAME``
~~~~~~~~~~~~~~~~~~~~~~

Default: ``"django_device"``

The name of the cookie.

``DEVICE_COOKIE_PERIOD``
~~~~~~~~~~~~~~~~~~~~~~~~

Default: ``timedelta(minutes=15)``

The period over which failed attempts count.

``DEVICE_COOKIE_ATTEMPTS_PER_PERIOD``
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Default: ``5``

The number of failed attempts in one period that locks out a device, or all
untrusted clients of an account.

``DEVICE_COOKIE_MAX_AGE``
~~~~~~~~~~~~~~~~~~~~~~~~~

Default: ``timedelta(days=365)``

How long the cookie stays valid.

``DEVICE_COOKIE_SECURE``
~~~~~~~~~~~~~~~~~~~~~~~~

Default: ``True``

Whether to use a secure cookie for the device cookie. If this is set to ``True``,
the cookie will be marked as "secure", which means browsers may ensure that
the cookie is only sent with an HTTPS connection.

``DEVICE_COOKIE_SAMESITE``
~~~~~~~~~~~~~~~~~~~~~~~~~~

Default: ``"Lax"``

The value of the SameSite flag on the device cookie.
This flag prevents the cookie from being sent in cross-site requests.

``DEVICE_COOKIE_DOMAIN``
~~~~~~~~~~~~~~~~~~~~~~~~

Default: ``None``

The domain to use for device cookies.
Set this to a string such as "example.com" for cross-domain cookies,
or use None for a standard domain cookie.

``DEVICE_COOKIE_PATH``
~~~~~~~~~~~~~~~~~~~~~~

Default: ``"/"``

The path of the cookie.

``DEVICE_COOKIE_PER_USER``
~~~~~~~~~~~~~~~~~~~~~~~~~~

Default: ``False``

Whether to set one cookie per user instead of one per browser. With ``False``,
each login replaces the browser's cookie, and only the last account to log in
from a browser stays trusted on it. When set to ``True``, every account that
logs in from a browser stays trusted on it, and the browser sends one cookie
per account.

``DEVICE_COOKIE_REVOKE_AFTER_FAILURES``
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Default: ``None``

The number of failed attempts over a cookie's life after which it is no longer
trusted. A stolen cookie gives its holder ``DEVICE_COOKIE_ATTEMPTS_PER_PERIOD``
guesses per period for as long as the cookie lives.
The package then keeps each device's failed attempts until its cookie expires.
A common value is ten times ``DEVICE_COOKIE_ATTEMPTS_PER_PERIOD``.

``DEVICE_COOKIE_HIDE_LOCKOUTS``
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Default: ``True``

Whether a locked-out attempt fails exactly like a wrong password, with the
form's usual error and the same password hashing time. Set it to ``False`` to
tell the user what happened. Setting this to ``True`` increases security at
the cost of user-friendly error messages for legitimate users.

Lockouts
--------

By default, a locked-out user sees the login form's usual error, as if the
password were wrong.

With ``DEVICE_COOKIE_HIDE_LOCKOUTS = False``, the user sees this instead:

    Too many failed attempts. Try again later.

If you add one of the package's password reset views, the message also says
that confirming a password reset in the same browser will clear the lockout.

The message needs the limit reached with one identifier. Attempts with another
identifier for the same account, such as its email address, fail like a wrong
password until that identifier reaches the limit too. This keeps the message
from revealing which email address belongs to a username.

The message is a form error, raised from ``authenticate()`` as
``django_device_cookies.exceptions.LockedOutError``. The admin and any form
built on ``AuthenticationForm`` show it, as long as the template renders the
form's errors. Code that calls ``authenticate()`` outside a form gets a 429
response with the message as plain text.

Password reset
--------------

An attacker can keep the untrusted lockout for an account in place, which
blocks its user from logging in from a new device. OWASP suggests issuing a
device cookie when the user visits a password reset link, since that proves
possession of the email account. An actual password reset is not necessary.
The package's password reset views do this. Add the one for your login flow to
your URLs, before the include that provides the flow.

For Django's password reset link:

.. code-block:: python

    from django_device_cookies.views import PasswordResetConfirmView

    path(
        "accounts/reset/<uidb64>/<token>/",
        PasswordResetConfirmView.as_view(),
        name="password_reset_confirm",
    ),

It renders ``registration/password_reset_confirm.html``, like Django's view.

For allauth's password reset link:

.. code-block:: python

    from django_device_cookies.allauth import PasswordResetFromKeyView

    re_path(
        r"^accounts/password/reset/key/(?P<uidb36>[0-9A-Za-z]+)-(?P<key>.+)/$",
        PasswordResetFromKeyView.as_view(),
        name="account_reset_password_from_key",
    ),

For allauth's password reset code, with
``ACCOUNT_PASSWORD_RESET_BY_CODE_ENABLED``:

.. code-block:: python

    from django_device_cookies.allauth import ConfirmPasswordResetCodeView

    path(
        "accounts/password/reset/confirm/",
        ConfirmPasswordResetCodeView.as_view(),
        name="account_confirm_password_reset_code",
    ),

The email address is found only through the user model's email field.
Allauth's email address model is not used.
A username that looks like an email address is trusted only when it is the
account's own email address. Any other email-shaped username never trusts a
device cookie, and its failed attempts count against the address rather than
against an account.
Logging in with a phone number is not throttled.

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
* **device_cookies.W003**: Django blanks out ``USERNAME_FIELD`` ``<field>`` in
  the ``user_login_failed`` signal, as its name looks like a secret. Failed
  calls to ``authenticate()`` that pass it by that name and have no request
  are not counted.

This check runs only with the ``--deploy`` option:

* **device_cookies.W002**: ``DEVICE_COOKIE_SECURE`` is off. Browsers send
  device cookies over HTTP.

.. _`device cookies`: https://owasp.org/www-community/Slow_Down_Online_Guessing_Attacks_with_Device_Cookies
