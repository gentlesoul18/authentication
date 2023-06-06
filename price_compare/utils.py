import requests
import datetime
from datetime import datetime
from typing import Tuple
from django.core.mail import EmailMessage
from django.utils import timezone
from django.core.management.utils import get_random_secret_key
from django.http import HttpResponse
from django.db import transaction
from django.utils import timezone
from rest_framework import serializers, status
from rest_framework.exceptions import APIException
from authentication.exceptions import PlainValidationError
from authentication.models import User

class PlainValidationError(APIException):
    """
    Utils used to raise JSON Validation error 
    instead of the django dictionary-list error
    """
    status_code = status.HTTP_400_BAD_REQUEST
    default_detail = ("Invalid input.")
    default_code = "invalid"

    def __init__(self, detail=None, code=None):
        if not isinstance(detail, dict):
            raise serializers.ValidationError("Invalid Input")
        self.detail = detail

def send_mail(data):
    """
    For sending mail in the app
    """
    mail = EmailMessage(
        subject=data['email_subject'],
        body=data['email_body'],
        from_email=data['from_email'],
        to=data['to_email']
    )
    return mail.send()


def get_now() -> datetime:
    return timezone.now()


def get_first_matching_attr(obj, *attrs, default=None):
    for attr in attrs:
        if hasattr(obj, attr):
            return getattr(obj, attr)

    return default


def get_error_message(exc) -> str:
    if hasattr(exc, 'message_dict'):
        return exc.message_dict
    error_msg = get_first_matching_attr(exc, 'message', 'messages')

    if isinstance(error_msg, list):
        error_msg = ', '.join(error_msg)

    if error_msg is None:
        error_msg = str(exc)

    return error_msg


def status_changer(status):
    if status == "1":
        return 'Backlog'
    elif status == "2":
        return 'In-Progress'
    elif status == "3":
        return 'Finished'
    elif status == "4":
        return 'Over-Due'
    elif status=="5":
        return 'Trash'
    else:
        return {'message': 'Id doesnt exist'} 



GOOGLE_USER_INFO_URL = "https://www.googleapis.com/oauth2/v1/userinfo"
APPLE_USER_INFO_URL = "https://api.apple.com/auth/userinfo"
FACEBOOK_USER_INFO_URL = "https://graph.facebook.com/me"

def get_now() -> datetime:
    return timezone.now()


def jwt_login(*, response: HttpResponse, user: User) -> HttpResponse:
    # generates access token to authenticate user that logs in with google
    token = user.token()

    return token


def get_google_user_info(access_token: str):  # -> Dict[str, Any]
    scope = 'profile email'
    response = requests.get(
        GOOGLE_USER_INFO_URL, params={"access_token": access_token, "scope":scope, "alt": "json"}
    )

    if not response.ok:
        print(response.json())
        raise PlainValidationError(
            {"message": "Failed to obtain user info from Google."}
        )

    return response.json()


def get_apple_user_info(access_token: str):  # -> Dict[str, Any]
    response = requests.get(
        APPLE_USER_INFO_URL, params={"access_token": access_token, "alt": "json"}
    )

    if not response.ok:
        print(response.json())
        raise PlainValidationError(
            {"detail": "Failed to obtain user info from apple."}
        )

    return response.json()


def get_facebook_user_info(access_token: str):  # -> Dict[str, Any]
    fields = 'email, name, picture'
    response = requests.get(
        FACEBOOK_USER_INFO_URL, params={"access_token": access_token, "fields":fields, "alt": "json"}
    )

    if not response.ok:
        print(response.json())
        raise PlainValidationError(
            {"detail": "Failed to obtain user info from facebook."}
        )

    return response.json()



def user_create(username, password=None, **extra_fields) -> User:
    extra_fields = {
        "is_staff": False,
        "is_superuser": False,
        "user_type": "C",
        **extra_fields,
    }

    user = User(username=username, **extra_fields)

    if password:
        user.set_password(password)
    else:
        user.set_unusable_password()

    user.full_clean()
    user.save()

    return user


def user_create_superuser(username, password=None, **extra_fields) -> User:
    extra_fields = {**extra_fields, "is_staff": True, "is_superuser": True}

    user = user_create(username=username).token

    return user


def user_record_login(*, user: User) -> User:
    user.last_login = get_now()
    user.save()

    return user


def trim_whitespace(string) -> str:
    return string.replace(" ", "")



def encouple_username(username, shop_id):
    return f"{username}:{shop_id}"

def decouple_username(username):
    splitted_username = username.split(":")
    return splitted_username[0]

@transaction.atomic
def user_change_secret_key(*, user: User) -> User:
    user.secret_key = get_random_secret_key()
    user.full_clean()
    user.save()

    return user



@transaction.atomic
def user_get_or_create(email, first_name, last_name) -> Tuple[User, bool]:
    if email == None:
        email = first_name.lower()+last_name.lower()+"@x.com"
    else:
        email = email
    user = User.objects.filter(username=email).first()

    # after querying user from database, if user exist, it return user
    if user:
        return user

    # else it creates the user with the info that we got from the user's mail
    user = user_create(first_name = first_name, last_name = last_name, username = email, email = email)
    return user