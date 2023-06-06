from django.db import IntegrityError, transaction
from django.db.models import Q
from django.core.exceptions import ObjectDoesNotExist
from django.http import Http404
from rest_framework.generics import GenericAPIView
from rest_framework.exceptions import ValidationError
from rest_framework.decorators import api_view, permission_classes
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from rest_framework.views import APIView
from rest_framework import status
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi
from authentication.exceptions import AccountNotRegisteredException, EmailAlreadyExistsException, PhoneAlreadyExistsException, SecurityCodeNotSentException, VoidDataException
from price_compare.mixins import ApiErrorsMixin, ApiAuthMixin, PublicApiMixin
from price_compare.utils import (
    user_get_or_create,
    get_apple_user_info,
    get_facebook_user_info,
    get_google_user_info,
    jwt_login,
)
from authentication.serializers import (
    SocialLoginSerializer,
    UserSerializer,
    RegisterSerializer,
)
from authentication.models import PhoneNumber, TempUser, User
from price_compare.utils import decouple_username, encouple_username, get_apple_user_info, get_facebook_user_info, get_google_user_info, trim_whitespace


# Create your views here.

class AppleLogin(APIView):
    """
    Google Login View to log user in with just a click
    parameter needed: code sent to google from frontend
    The code is used to generate users access token then the access token,
    the access token is then used to generate the user's data from google
    """

    serializer_class = SocialLoginSerializer

    def post(self, request):
        code = request.data["auth_token"]
        user_data = get_apple_user_info(access_token=code)
        print(user_data)

        email = user_data["email"]
        first_name = user_data["given_name"]
        last_name = user_data["family_name"]

        user = user_get_or_create(email, first_name, last_name)

        response = Response()
        token = jwt_login(response=response, user=user)
        response.data = {**user_data, "token": token}

        return response


class FacebookLogin(GenericAPIView):
    serializer_class = SocialLoginSerializer

    def post(self, request):
        """
        POST with "auth_token"
        Send an access token as from facebook to get user information
        """
        auth_token = request.data["auth_token"]
        
        user_data = get_facebook_user_info(access_token=auth_token)
        email = user_data.get("email")
        name = user_data.get("name").split(" ")
        first_name = name[0]
        last_name = name[1]
        user = user_get_or_create(email, first_name, last_name)

        response = Response()
        token = jwt_login(response=response, user=user)
        response.data = {**user_data, "token": token}
        return response


@api_view(["POST"])
def check_user_exist_or_login(request):
    data = request.data
    username = trim_whitespace(data["username"])



    user = User.objects.filter(username = username).exists()

    if user:
        try:
            user = User.objects.get(username=username)
            user_phone = PhoneNumber.objects.filter(user__username=user).first()
        except ObjectDoesNotExist:
            raise Http404

        phone_number = str(user_phone.phone_number)
        sent = user_phone.send_confirmation
        if sent:
            return Response(
                {
                    "detail": f"Verification code has been sent to {phone_number[0:5]}*****{phone_number[len(phone_number)-2:len(phone_number)]}, please check to proceed"
                }
            )
        else:
            raise SecurityCodeNotSentException.default_detail
    else:
        raise AccountNotRegisteredException


@transaction.atomic
@api_view(["POST"])
def register_user(request):
    data = request.data
    username = trim_whitespace(data["username"])
    first_name = trim_whitespace(data["firstName"])
    last_name = trim_whitespace(data["lastName"])
    email = trim_whitespace(data["username"])
    phone_number = trim_whitespace(data["phoneNumber"])
    user_type = trim_whitespace(data["userType"])
    shop_id = data["shopId"]
    if user_type == "C":
        username = encouple_username(username, shop_id)
    elif user_type == "M":
        username = username
    else:
        return Response(
            {"detail": "invalid user type"}, status=status.HTTP_400_BAD_REQUEST
        )
    try:
        try:
            user = User.objects.create(
                username=username,
                first_name=first_name,
                last_name=last_name,
                email=email,
                user_type=user_type,
            )
        except EmailAlreadyExistsException:
            raise EmailAlreadyExistsException
        try:
            PhoneNumber.objects.create(user=user, phone_number=phone_number)
        except PhoneAlreadyExistsException:
            raise PhoneAlreadyExistsException

        token = user.token()

        response = Response()
        response.data = {"token": token}
        return response

    except IntegrityError as e:
        if "phone_number" in str(e):
            raise PhoneAlreadyExistsException
        elif "username" in str(e):
            raise EmailAlreadyExistsException


@permission_classes([IsAuthenticated])
@api_view(["GET"])
def get_user_details(request):
    user = request.user
    user_phone_number = PhoneNumber.objects.get(user=user)
    user_details = {
        "username": user.decouple_username(),
        "first_name": user.first_name,
        "last_name": user.last_name,
        "email": user.email,
        "phone_number": user_phone_number.phone_number.as_e164,
    }
    return Response({**user_details})


@api_view(["POST"])
def send_security_code(request):
    data = request.data
    phone_number = data["phoneNumber"]

    if phone_number:
        temp_phone_number = TempUser.objects.create(phone_number=phone_number)
        sent = temp_phone_number.send_confirmation

        # checking if the security is sent successfully
        if sent:
            return Response(
                {
                    "detail": f"Security code sent to {phone_number[0:5]}*****{phone_number[len(phone_number)-2:len(phone_number)]}"
                }
            )
        else:
            return Response({"detail": "Not sent"})

    else:
        raise VoidDataException.default_detail


@api_view(["POST"])
def verify_security_code(request):
    data = request.data

    phone_number = data["phoneNumber"]
    security_code = data["securityCode"]

    user = PhoneNumber.objects.get(phone_number=phone_number)
    user_details = {
        "username": decouple_username(user.user.username),
        "first_name": user.user.first_name,
        "last_name": user.user.last_name,
        "email": user.user.email,
        "phone_number": phone_number,
    }

    if user:
        security_code_verified = user.check_verification(security_code)

        if security_code_verified:
            return Response(security_code_verified)
        return Response(
            {**user_details, "token": user.check_verification(security_code)}
        )
    else:
        user = TempUser.objects.get(phone_number=phone_number)

        security_code_verified = user.security_code_confirmation(security_code)
        return Response(security_code_verified)



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


class GoogleLogin(APIView):
    """
    Google Login View to log user in with just a click
    parameter needed: code sent to google from frontend
    The code is used to generate users access token then the access token,
    the access token is then used to generate the user's data from google
    """

    serializer_class = SocialLoginSerializer

    def post(self, request):
        code = request.data["auth_token"]
        user_data = get_google_user_info(access_token=code)
        
        email = user_data["email"]
        first_name = user_data["given_name"]
        last_name = user_data["family_name"]

        user = user_get_or_create(email, first_name, last_name)

        response = Response()
        token = jwt_login(response=response, user=user)
        response.data = {**user_data, "token": token}
        return response
