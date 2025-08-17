import datetime
from functools import wraps
import tornado.web
from settings import JWT_SECRET, JWT_CONFIG, PASSWORD_CONFIG, USERNAME_CONFIG, ERROR_MESSAGES
import jwt

def validate_credentials_format(username: str, password: str):
    if not username or not password:
        return ERROR_MESSAGES["auth_validation_error"]["credentials"]
    if not USERNAME_CONFIG["regex"].match(username):
        return ERROR_MESSAGES["auth_validation_error"]["username"]
    if not (PASSWORD_CONFIG["min_length"] <= len(password) <= PASSWORD_CONFIG["max_length"]):
        return ERROR_MESSAGES["auth_validation_error"]["password"]
    return None

def generate_jwt_token(user_id: str, username: str, role: str):
    now = datetime.datetime.now(datetime.timezone.utc)
    expiry = now + datetime.timedelta(minutes=JWT_CONFIG["exp_minutes"])
    payload = {
        "sub": user_id,
        "username": username,
        "role": role,
        "iss": JWT_CONFIG["issuer"],
        "iat": int(now.timestamp()),
        "exp": int(expiry.timestamp()),
    }
    token = jwt.encode(payload, JWT_SECRET, algorithm=JWT_CONFIG["algorithm"])
    return {"token": token, "expires_in": JWT_CONFIG["exp_minutes"] * 60}

def jwt_required(handler_method):
    @wraps(handler_method)
    async def wrapper(self, *args, **kwargs):
        if not self.current_user:
            auth_header = self.request.headers.get("Authorization", "")
            if not auth_header.startswith("Bearer "):
                raise tornado.web.HTTPError(401, reason="MISSING_TOKEN")
            raise tornado.web.HTTPError(401, reason="INVALID_TOKEN")
        return await handler_method(self, *args, **kwargs)
    return wrapper
