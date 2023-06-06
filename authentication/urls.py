from django.urls import path
from rest_framework_simplejwt.views import TokenRefreshView
from . import views

app_name = "authentication"

urlpatterns = [
    path("register", views.RegisterView.as_view(), name="register"),
    path("signin", views.LoginView.as_view(), name="signin"),
    path('register/', views.register_user, name='register'),
    path('send-otp/', views.send_security_code, name='send-otp'),
    path('verify-otp/', views.verify_security_code, name='verify-otp'),
    path("user-exists/", views.check_user_exist_or_login, name="user-identifier"),
    path("user-details/", views.get_user_details, name="user-details"),
    path('facebook/', views.FacebookLogin.as_view(), name='fb-login'),
    path('google/', views.GoogleLogin.as_view(), name='google-login'),
    path('apple/', views.AppleLogin.as_view(), name='google-login'),
    path('refresh-token/', TokenRefreshView.as_view(), name='refresh-token'),
]

