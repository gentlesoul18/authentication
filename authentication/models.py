from django.db import models
from django.contrib.auth.models import AbstractUser
from rest_framework_simplejwt.tokens import RefreshToken, AccessToken

# Create your models here.


class User(AbstractUser):
    is_verified = models.BooleanField(default=False)

    REQUIRED_FIELDS = []

    def tokens(self):
        access = AccessToken.for_user(self)
        return str(access)
