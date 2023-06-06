from django.utils.translation import gettext as _
from rest_framework.exceptions import APIException
from django.db import IntegrityError

from rest_framework import serializers, status


class AccountNotRegisteredException(APIException):
    status_code = 404
    default_detail = _("The account is not registered.")
    default_code = "non-registered-account"


class AccountDisabledException(APIException):
    status_code = 403
    default_detail = _("User account is disabled.")
    default_code = "account-disabled"


class PlainValidationError(APIException):
    """
    Utils used to raise JSON Validation error
    instead of the django dictionary-list error
    """

    status_code = status.HTTP_400_BAD_REQUEST
    default_detail = "Invalid input."
    default_code = "invalid"

    def __init__(self, detail=None, code=None):
        if not isinstance(detail, dict):
            raise serializers.ValidationError("Invalid Input")
        self.detail = detail


class InvalidCredentialsException(APIException):
    status_code = 401
    default_detail = _("Wrong username")
    default_code = "invalid-credentials"


class VoidDataException(APIException):
    status_code = 401
    default_detail = _("Empty data")
    default_code = "empty-data"


class EmailAlreadyExistsException(APIException):
    status_code = 400
    default_detail = _("Email already exists")
    default_code = "email-already-exists"

class PhoneAlreadyExistsException(APIException):
    status_code = 400
    default_detail = _("Phone already exists")
    default_code = "phone-already-exists"


class AccountAlreadyExistsException(IntegrityError):
    status_code = 405
    default_detail = _("User's account already exists")
    default_code = "user-already-exists"


class SecurityCodeNotSentException(APIException):
    status_code = 407
    default_detail = _("Security code not sent")
    default_code = "security-code-not-sent"
