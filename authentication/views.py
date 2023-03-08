from django.db.models import Q
from rest_framework.generics import GenericAPIView
from rest_framework.exceptions import ValidationError
from rest_framework.response import Response
from rest_framework.views import APIView
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi
from three60.mixins import ApiErrorsMixin, ApiAuthMixin, PublicApiMixin
from authentication.services import (
    user_get_or_create,
    google_get_user_info,
    jwt_login,
)
from authentication.serializers import (
    UserSerializer,
    RegisterSerializer,
    InputSerializer,
)
from authentication.models import User


# Create your views here.


class RegisterView(GenericAPIView, ApiAuthMixin):
    """
    View to sign up new user using normal registration
    """

    serializer_class = RegisterSerializer

    def post(self, request):

        serializer = RegisterSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        serializer.save()
        user_data = serializer.data
        user = User.objects.get(email=user_data["email"])
        token = user.tokens()
        response = Response()
        response.data = {**user_data, "access_token": token}
        return response


class LoginView(GenericAPIView):
    """
    View to Log in Existing Users
    """

    serializer_class = UserSerializer

    def post(self, request):
        username = request.data["username"]
        password = request.data["password"]
        try:
            user = User.objects.get(Q(username=username.lower()) | Q(email=username))
        except BaseException as e:
            raise ValidationError({"message": "This user does not exist"})

        if not user.check_password(password):
            raise ValidationError({"message": "Incorrect Password!"})

        serializer = UserSerializer(user)

        response = Response()
        token = user.tokens()
        response.set_cookie(
            key="jwt", value=token, httponly=True
        )  # creates cookies for user session
        response.data = {"access_token": token, **serializer.data}
        return response


class GoogleLoginApi(PublicApiMixin, ApiErrorsMixin, APIView):
    """
    Google Login View to log user in with just a click
    parameter needed: code sent to google from frontend
    The code is used to generate users access token then the access token,
    the access token is then used to generate the user's data from google
    """

    serializer_class = InputSerializer

    @swagger_auto_schema(
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                "code": openapi.Schema(type=openapi.TYPE_STRING, description="string"),
            },
        )
    )
    def post(self, request):

        code = request.data["code"]

        user_data = google_get_user_info(access_token=code)

        profile_data = {
            "email": user_data["email"],
            "username": user_data.get("given_name", ""),
        }

        # We use get-or-create logic here for the sake of the example.
        # We don't have a sign-up flow.

        user, _ = user_get_or_create(**profile_data)

        response = Response()
        token = jwt_login(response=response, user=user)
        response.data = {"access_token": token, **profile_data}

        return response
