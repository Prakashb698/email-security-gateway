from auth.password import verify_password
from auth.token import create_access_token
from database.user_repository import get_user_by_email


def authenticate_user(email: str, password: str):
    user = get_user_by_email(email)

    if not user:
        return None

    if not user["active"]:
        return None

    if not verify_password(password, user["password_hash"]):
        return None

    token = create_access_token(
        email=user["email"],
        domain_name=user["domain_name"]
    )

    return {
        "access_token": token,
        "token_type": "bearer"
    }
