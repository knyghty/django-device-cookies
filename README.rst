=====================
Django Device Cookies
=====================

DO NOT USE THIS IN REAL PROJECTS.

This is just a proof of concept.
It might be hideously broken.
It is definitely not performant.

This is a Django package that throttles login requests based on `device cookies`_.

Usage
-----

1. Add ``"django_device_cookies"`` to ``INSTALLED_APPS``
2. Add ``"django_device_cookies.middleware.DeviceCookieMiddleware"`` to ``MIDDLEWARE``
3. Add ``"django_device_cookies.backends.DeviceCookieBackend"``
    to the beginning of ``AUTHENTICATION_BACKENDS``

With default settings the package will allow 3 login attempts per hour per device,
where any unknown devices are treated as a single device.

Settings
--------

``DEVICE_COOKIE_NAME`` - the name of the cookie used. Defaults to ``django_device``.

``DEVICE_COOKIE_PERIOD`` - the period within which number of requests defined by
``DEVICE_COOKIE_REQUESTS_PER_PERIOD`` are allowed. This is also the lockout time.
Defaults to 1 hour.

``DEVICE_COOKIES_REQUESTS_PER_PERIOD`` - the number of requests allowed in the period defined by
``DEVICE_COOKIE_PERIOD``. Defaults to 3.

``DEVICE_COOKIE_SAMESITE`` - sets the ``SameSite`` attribute on the cookie. Defaults to ``Lax``.

``DEVICE_COOKIE_SECURE`` - sets the ``secure`` flag on the cookie. Defaults to ``True``.

Credits
-------

This package was created with Cookiecutter_ and the `knyghty/cookiecutter-django-package`_ project template.

.. _Cookiecutter: https://github.com/cookiecutter/cookiecutter
.. _`knyghty/cookiecutter-django-package`: https://github.com/knyghty/cookiecutter-django-package
.. _`device cookies`: https://owasp.org/www-community/Slow_Down_Online_Guessing_Attacks_with_Device_Cookies
