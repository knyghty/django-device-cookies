import pytest
from django.contrib.auth.models import User
from django.test import Client

from .helpers import create_user
from .helpers import login


@pytest.fixture
def user(db: None) -> User:
    return create_user("alice")


@pytest.fixture
def trusted(user: User) -> Client:
    client = Client()
    login(client)
    return client
