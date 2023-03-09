from django.core.mail import EmailMessage
from django.utils import timezone
from datetime import datetime

from rest_framework import serializers, status
from rest_framework.exceptions import APIException


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