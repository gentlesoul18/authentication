import datetime
from django.db import models
from django.conf import settings
from django.utils import timezone
from django.contrib.auth.models import AbstractUser
from django.utils.translation import gettext as _
from django.utils.crypto import get_random_string
from phonenumber_field.modelfields import PhoneNumberField
from rest_framework.exceptions import NotAcceptable
from rest_framework_simplejwt.tokens import AccessToken, RefreshToken
from twilio.rest import Client
from twilio.base.exceptions import TwilioRestException
from django_countries.fields import CountryField


# Create your models here.
class User(AbstractUser):
    USER_TYPE = (
        ("M", "MERCHANT"),
        ("C", "CUSTOMER"),
    )
    username = models.CharField(max_length=50, unique=True, null=True, blank=True)
    user_type = models.CharField(
        max_length=15, choices=USER_TYPE, default=USER_TYPE[1], null=True, blank=True
    )

    USERNAME_FIELD = "username"

    

    def __str__(self) -> str:
        return self.username
    
    def decouple_username(self):
        splitted_username = self.username.split(":")
        return splitted_username[0]

    def token(self):
        access = AccessToken.for_user(self)
        refresh = RefreshToken.for_user(self)
        return f"refresh_token:  {refresh}    access_token: {access}"


class PhoneNumber(models.Model):
    user = models.OneToOneField(
        User, related_name="phone", on_delete=models.CASCADE, null=True, blank=True
    )
    phone_number = PhoneNumberField()
    security_code = models.CharField(max_length=120)
    is_verified = models.BooleanField(default=False)
    sent = models.DateTimeField(null=True)

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ("-created_at",)

    def __str__(self):
        return self.phone_number.as_e164

    

    def generate_security_code(self):
        # Returns a unique random `security_code` for given `TOKEN_LENGTH` in the settings.
        # Default token length = 6

        token_length = getattr(settings, "TOKEN_LENGTH", 6)
        return get_random_string(token_length, allowed_chars="0123456789")

    def is_security_code_expired(self):
        expiration_date = self.sent + datetime.timedelta(
            minutes=settings.TOKEN_EXPIRE_MINUTES
        )
        return expiration_date <= timezone.now()

    @property
    def send_confirmation(self):
        twilio_account_sid = settings.TWILIO_ACCOUNT_SID
        twilio_auth_token = settings.TWILIO_AUTH_TOKEN
        twilio_phone_number = settings.TWILIO_PHONE_NUMBER

        self.security_code = self.generate_security_code()

        if all([twilio_account_sid, twilio_auth_token, twilio_phone_number]):
            try:
                twilio_client = Client(twilio_account_sid, twilio_auth_token)
                twilio_client.messages.create(
                    body=f"Your activation code is {self.security_code}",
                    to=str(self.phone_number),
                    from_=twilio_phone_number,
                )
                self.sent = timezone.now()
                self.save()
                return True
            except TwilioRestException as e:
                return e
        else:
            print("Twilio credentials are not set")

    def check_verification(self, security_code):
        if (
            not self.is_security_code_expired()
            and security_code == self.security_code
            and self.is_verified == False
        ):
            self.is_verified = True
            self.save()
            return self.is_verified

        elif (
            not self.is_security_code_expired()
            and security_code == self.security_code
            and self.is_verified == True
        ):
            return self.user.token()

        else:
            raise NotAcceptable(_("Existed, expired or wrong code"))


class TempUser(models.Model):
    phone_number = models.CharField(max_length=15)
    security_code = models.CharField(
        max_length=6, default="000000", blank=True, null=True
    )
    sent = models.DateTimeField(null=True)

    def is_security_code_expired(self):
        expiration_date = self.sent + datetime.timedelta(
            minutes=settings.TOKEN_EXPIRE_MINUTES
        )
        return expiration_date <= timezone.now()

    def generate_security_code(self):
        # Returns a unique random `security_code` for given `TOKEN_LENGTH` in the settings.
        # Default token length = 6

        token_length = getattr(settings, "TOKEN_LENGTH", 6)
        return get_random_string(token_length, allowed_chars="0123456789")

    @property
    def send_confirmation(self):
        twilio_account_sid = settings.TWILIO_ACCOUNT_SID
        twilio_auth_token = settings.TWILIO_AUTH_TOKEN
        twilio_phone_number = settings.TWILIO_PHONE_NUMBER

        self.security_code = self.generate_security_code()

        if all([twilio_account_sid, twilio_auth_token, twilio_phone_number]):
            try:
                twilio_client = Client(twilio_account_sid, twilio_auth_token)
                twilio_client.messages.create(
                    body=f"Your activation code is {self.security_code}",
                    to=str(self.phone_number),
                    from_=twilio_phone_number,
                )
                self.sent = timezone.now()
                self.save()
                return True
            except TwilioRestException as e:
                return e
        else:
            print("Twilio credentials are not set")

    def security_code_confirmation(self, security_code):
        if not self.is_security_code_expired() and security_code == self.security_code:
            return {"verified": True}

        else:
            raise NotAcceptable(_("Existed, expired or wrong code"))

    # TODO: verify function return phone number is verifed -> boolean

    def __str__(self) -> str:
        return self.phone_number


class Address(models.Model):
    # Address options
    BILLING = "B"
    SHIPPING = "S"

    ADDRESS_CHOICES = ((BILLING, _("billing")), (SHIPPING, _("shipping")))

    user = models.ForeignKey(User, related_name="addresses", on_delete=models.CASCADE)
    address_type = models.CharField(max_length=1, choices=ADDRESS_CHOICES)
    default = models.BooleanField(default=False)
    country = CountryField(null=True, blank=True)
    city = models.CharField(max_length=100)
    street_address = models.CharField(max_length=100)
    apartment_address = models.CharField(max_length=100, null=True, blank=True)
    postal_code = models.CharField(max_length=20, blank=True)

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ("-created_at",)

    def __str__(self):
        return self.user.get_full_name()


class TempUser(models.Model):
    phone_number = models.CharField(max_length=15)
    security_code = models.CharField(
        max_length=6, default="000000", blank=True, null=True
    )
    sent = models.DateTimeField(null=True)

    def is_security_code_expired(self):
        expiration_date = self.sent + datetime.timedelta(
            minutes=settings.TOKEN_EXPIRE_MINUTES
        )
        return expiration_date <= timezone.now()

    def generate_security_code(self):
        # Returns a unique random `security_code` for given `TOKEN_LENGTH` in the settings.
        # Default token length = 6

        token_length = getattr(settings, "TOKEN_LENGTH", 6)
        return get_random_string(token_length, allowed_chars="0123456789")

    @property
    def send_confirmation(self):
        twilio_account_sid = settings.TWILIO_ACCOUNT_SID
        twilio_auth_token = settings.TWILIO_AUTH_TOKEN
        twilio_phone_number = settings.TWILIO_PHONE_NUMBER

        self.security_code = self.generate_security_code()

        if all([twilio_account_sid, twilio_auth_token, twilio_phone_number]):
            try:
                twilio_client = Client(twilio_account_sid, twilio_auth_token)
                twilio_client.messages.create(
                    body=f"Your activation code is {self.security_code}",
                    to=str(self.phone_number),
                    from_=twilio_phone_number,
                )
                self.sent = timezone.now()
                self.save()
                return True
            except TwilioRestException as e:
                return e
        else:
            print("Twilio credentials are not set")

    def security_code_confirmation(self, security_code):
        if not self.is_security_code_expired() and security_code == self.security_code:
            return {"verified": True}

        else:
            raise NotAcceptable(_("Existed, expired or wrong code"))

    # TODO: verify function return phone number is verifed -> boolean

    def __str__(self) -> str:
        return self.phone_number
