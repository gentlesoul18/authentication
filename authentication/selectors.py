from authentication.models import User


def get_user(*, user: User):
    return {"id": user.id, "username": user.name, "email": user.email}


def jwt_response_payload_handler(token, user=None, request=None):
    return {
        "token": token,
        "user": get_user(user=user),
    }
