=====================
Django Device Cookies
=====================

Throttle login attempts with `device cookies`_. The throttle locks out an
attacker who guesses passwords. It does not lock out the account's owner on a
browser that logged in before.

How it works
------------

A device cookie is a signed cookie that holds the username and a nonce (a random
value that identifies the browser). Each successful login sets a new one. The
backend sorts each call to ``authenticate()`` into a bucket (a count of failed
attempts). If the request carries a valid cookie for that username, the bucket
is the cookie's nonce. If not, the bucket is the untrusted bucket that all
other clients of that username share.

A bucket is locked while it holds ``DEVICE_COOKIE_ATTEMPTS_PER_PERIOD`` failed
attempts from the last ``DEVICE_COOKIE_PERIOD``. It opens again as the oldest
of them age out. The backend rejects each attempt on a locked bucket before it
checks the password.
Unknown usernames get the same treatment, so the throttle does not show which
accounts exist.

Installation
------------

1. Add ``"django_device_cookies"`` to ``INSTALLED_APPS``.
2. Add ``"django_device_cookies.middleware.DeviceCookieMiddleware"`` to
   ``MIDDLEWARE``.
3. Set ``AUTHENTICATION_BACKENDS`` to
   ``["django_device_cookies.backends.DeviceCookieModelBackend"]``.
4. Run ``migrate``.

``DeviceCookieModelBackend`` is Django's ``ModelBackend`` with the throttle in
front. If your project uses other backends, put
``"django_device_cookies.backends.DeviceCookieBackend"`` first in
``AUTHENTICATION_BACKENDS`` instead. That backend only throttles. It does not
authenticate. With more than one backend, a ``login()`` call whose user did not
come from ``authenticate()`` must pass ``backend``. System checks report a
missing backend, a missing middleware, and a backend that is not first.

Settings
--------

Each setting has a default.

``DEVICE_COOKIE_NAME``
    The cookie name. Default ``"django_device"``.

``DEVICE_COOKIE_PERIOD``
    A ``timedelta``. The throttle counts the failed attempts in this period.
    Default 15 minutes.

``DEVICE_COOKIE_ATTEMPTS_PER_PERIOD``
    The failed attempts that each bucket lets through in one period. Default
    ``5``.

``DEVICE_COOKIE_MAX_AGE``
    A ``timedelta``. The cookie expires after this time. Default one year.

``DEVICE_COOKIE_SECURE``
    Send the cookie over HTTPS only. Default ``True``. If you develop over
    HTTP, set it to ``False``.

``DEVICE_COOKIE_SAMESITE``
    The ``SameSite`` attribute of the cookie. Default ``"Lax"``.

``DEVICE_COOKIE_DOMAIN``
    The ``Domain`` attribute of the cookie. Default ``None``.

``DEVICE_COOKIE_PATH``
    The ``Path`` attribute of the cookie. Default ``"/"``.

``DEVICE_COOKIE_PER_USER``
    Set one cookie per user, so that people who share a browser each keep
    their own trust. The cookie name gets a hash of the username. Default
    ``False``: one cookie per browser, which each login replaces.

``DEVICE_COOKIE_REVOKE_AFTER_FAILURES``
    Stop trusting a device cookie after this many failures over its life. This
    limits what a stolen cookie is worth. The package then keeps each device's
    failed attempts until its cookie expires. Default ``None`` (off). OWASP
    suggests ten times ``DEVICE_COOKIE_ATTEMPTS_PER_PERIOD``.

Recovering a locked-out client
------------------------------

An attacker who keeps guessing keeps the untrusted bucket locked. While the
attack lasts, the account's owner cannot log in from a new browser, even after
a password reset. A valid password reset link proves control of the account's
email. So when the user opens the link,
``django_device_cookies.views.PasswordResetConfirmView`` sets a device cookie.
The user does not have to change the password afterwards. To use it, route it
in place of Django's view:

.. code-block:: python

    from django_device_cookies.views import PasswordResetConfirmView

    path(
        "accounts/reset/<uidb64>/<token>/",
        PasswordResetConfirmView.as_view(),
        name="password_reset_confirm",
    ),

Put it before ``include("django.contrib.auth.urls")`` so that it takes
priority. If your project has its own reset view, subclass this one instead of
Django's.

The view renders the same template as Django's view,
``registration/password_reset_confirm.html``, and takes the same attributes,
such as ``template_name``. The admin app ships a version of that template. To
use your own, put a template at that path in a directory that Django searches
before the admin's, such as one of the ``DIRS`` in your ``TEMPLATES`` setting.

Other measures
--------------

The throttle limits the guesses at one account. It does not limit an attacker
who tries one password against many accounts. When many accounts see failed
attempts in a short time, OWASP suggests a CAPTCHA for untrusted clients. This
package does not do that, but the ``lockout`` signal below lets you count
lockouts across accounts and act. Also keep Django's password validators on,
so that the few guesses an attacker gets are unlikely to succeed.

Signals
-------

Each lockout logs a warning to the ``django_device_cookies`` logger. It also
sends the ``django_device_cookies.signals.lockout`` signal with three
arguments: ``username`` (the bucket key), ``device`` (the cookie nonce, or
``""`` for untrusted clients) and ``request``. If ``authenticate()`` ran
without a request, ``request`` is ``None``. Connect a receiver to tell an
operator or the account's owner. A revocation logs a warning too.

Maintenance
-----------

The package keeps failed attempts in the database. Run
``manage.py clear_device_cookie_attempts`` on a schedule to remove the attempts
that no longer count. To lift a lockout early, remove the user's rows in the
admin.

Limitations
-----------

- The throttle sees an attempt only through a call to
  ``django.contrib.auth.authenticate()``. Django's login views, the admin and
  REST framework's basic authentication make that call. Code that calls
  ``user.check_password()`` itself gets no throttle. Pass the request to
  ``authenticate()``, or every attempt counts as untrusted.
- A locked client can drop its cookie and use the untrusted bucket. So a
  client with a cookie can make two times ``DEVICE_COOKIE_ATTEMPTS_PER_PERIOD``
  attempts.
- The package counts a failure after the password check. Requests that come at
  the same moment can all pass the gate.
- The backend rejects an attempt on a locked bucket with the same response,
  and after the same password hashing time, as for incorrect credentials.
  Login forms show their usual error.
- The cookie holds the username, base64 encoded.
- The database keeps every submitted username in plain text until the cleanup
  command removes it. That includes a password that a user typed into the
  username field.
- Lockouts count against the account that the user model's natural key lookup
  finds for the typed username, so every spelling that lookup accepts shares
  one bucket. Unknown usernames get a bucket per case and Unicode variant. The
  package trusts a device cookie only for the account it was set for.
- Every call to ``login()`` sets a device cookie, including calls from tools
  that let staff act as another user.
- If ``ATOMIC_REQUESTS`` is on, the package records a failure only after the
  view's transaction commits.
- Django masks credential names that contain ``api``, ``token``, ``key``,
  ``secret``, ``password`` or ``signature`` in ``user_login_failed``. The
  throttle ignores callers that pass such a ``USERNAME_FIELD`` to
  ``authenticate()`` by name. Django's login form passes ``username``, so it is
  not affected. A system check warns about this.

Cookiecutter_ and the `knyghty/cookiecutter-django-package`_ template made the
first version of this package.

.. _Cookiecutter: https://github.com/cookiecutter/cookiecutter
.. _`knyghty/cookiecutter-django-package`: https://github.com/knyghty/cookiecutter-django-package
.. _`device cookies`: https://owasp.org/www-community/Slow_Down_Online_Guessing_Attacks_with_Device_Cookies
