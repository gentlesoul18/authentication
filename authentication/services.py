from typing import Tuple, Dict, Any
from typing import Tuple
from django.core.management.utils import get_random_secret_key
from django.core.exceptions import ValidationError
from django.conf import settings
from django.http import HttpResponse
from django.db import transaction
from three60.utils import get_now, PlainValidationError
from authentication.models import User
import requests


GOOGLE_USER_INFO_URL = "https://www.googleapis.com/oauth2/v1/userinfo"


def jwt_login(*, response: HttpResponse, user: User) -> HttpResponse:
    token = (
        user.tokens()
    )  # generates access token to authenticate user that logs in with google

    return token


def google_get_user_info(access_token: str):  # -> Dict[str, Any]
    # Reference: https://developers.google.com/identity/protocols/oauth2/web-server#callinganapi
    response = requests.get(
        GOOGLE_USER_INFO_URL, params={"access_token": access_token, "alt": "json"}
    )

    if not response.ok:
        print(response.json())
        raise PlainValidationError(
            {"message": "Failed to obtain user info from Google."}
        )

    return response.json()


def user_create(email, password=None, **extra_fields) -> User:
    extra_fields = {"is_staff": False, "is_superuser": False, **extra_fields}

    user = User(email=email, **extra_fields)

    if password:
        user.set_password(password)
    else:
        user.set_unusable_password()

    user.full_clean()
    user.save()

    return user


def user_create_superuser(email, password=None, **extra_fields) -> User:
    extra_fields = {**extra_fields, "is_staff": True, "is_superuser": True}

    user = user_create(email=email, password=password, **extra_fields)

    return user


def user_record_login(*, user: User) -> User:
    user.last_login = get_now()
    user.save()

    return user


@transaction.atomic
def user_change_secret_key(*, user: User) -> User:
    user.secret_key = get_random_secret_key()
    user.full_clean()
    user.save()

    return user


@transaction.atomic
def user_get_or_create(*, email: str, **extra_data) -> Tuple[User, bool]:
    user = User.objects.filter(email=email).first()
    # after querying user from database, if user exist, it return user
    if user:
        return user, False
    # else it creates the user with the info that we got from the user's mail
    return user_create(email=email, **extra_data), True
