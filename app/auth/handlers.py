import json
import logging
import datetime
from functools import wraps
from typing import Dict, Any, Optional

import bcrypt
import jwt
import tornado.web
from tornado.escape import json_decode
from tornado.ioloop import IOLoop

from services.es import es
from elasticsearch import ConflictError
from configurations import (
    JWT_SECRET,
    JWT_CONFIG,
    PASSWORD_CONFIG,
    USERNAME_CONFIG,
    ES_CONFIG,
    HTTP_CONFIG,
    ERROR_MESSAGES,
)

logger = logging.getLogger(__name__)

# Utilities (async offloading)
async def es_io(fn, *a, **kw):
    return await IOLoop.current().run_in_executor(None, lambda: fn(*a, **kw))

async def cpu_io(fn, *a, **kw):
    return await IOLoop.current().run_in_executor(None, lambda: fn(*a, **kw))


class BaseHandler(tornado.web.RequestHandler):
    """
    Common JSON/CORS/error/JWT utilities.
    - prepare(): parse JSON body and (optionally) decode JWT into self.current_user
    - write_error(): centralized JSON error envelope
    - set_default_headers()/options(): CORS
    """
    def set_default_headers(self):
        for header, value in HTTP_CONFIG["default_headers"].items():
            self.set_header(header, value)

    def prepare(self):
        self.json: Optional[Dict[str, Any]] = None
        ctype = self.request.headers.get("Content-Type", "")
        if ctype.startswith("application/json"):
            try:
                self.json = json_decode(self.request.body or b"{}")
            except Exception as e:
                raise tornado.web.HTTPError(400, reason="INVALID_JSON") from e

        self.current_user = None
        auth_header = self.request.headers.get("Authorization", "")
        if auth_header.startswith("Bearer "):
            token = auth_header.split(" ", 1)[1].strip()
            try:
                payload = jwt.decode(
                    token,
                    JWT_SECRET,
                    algorithms=[JWT_CONFIG["algorithm"]],
                    options={
                        "require": JWT_CONFIG["required_claims"],
                        "verify_exp": True,
                        "verify_iat": True,
                    },
                    issuer=JWT_CONFIG["issuer"],
                )
                self.current_user = {
                    "user_id": payload.get("sub"),
                    "username": payload.get("username"),
                    "role": payload.get("role", ES_CONFIG["default_role"]),
                    "payload": payload,
                }
            except Exception:
                pass

    def options(self, *args, **kwargs):
        req_headers = self.request.headers.get("Access-Control-Request-Headers")
        if req_headers:
            self.set_header("Access-Control-Allow-Headers", req_headers)
        req_method = self.request.headers.get("Access-Control-Request-Method")
        if req_method:
            self.set_header("Access-Control-Allow-Methods", req_method)
        self.set_status(204)
        self.finish()

    def write_error(self, status_code: int, **kwargs):
        reason = kwargs.get("reason") or getattr(self, "_reason", "") or "ERROR"

        default_msg = ERROR_MESSAGES.get("unknown_error", "Something went wrong")
        map_simple = {
            "INVALID_JSON": ("INVALID_JSON", ERROR_MESSAGES["invalid_json"]),
            "INVALID_CREDENTIALS": ("INVALID_CREDENTIALS", ERROR_MESSAGES["invalid_credentials"]),
            "USERNAME_TAKEN": ("USERNAME_TAKEN", ERROR_MESSAGES["username_taken"]),
            "MISSING_TOKEN": ("MISSING_TOKEN", ERROR_MESSAGES["missing_token"]),
            "INVALID_TOKEN": ("INVALID_TOKEN", ERROR_MESSAGES["invalid_token"]),
            "REGISTRATION_FAILED": ("REGISTRATION_FAILED", ERROR_MESSAGES["registration_failed"]),
            "LOGIN_FAILED": ("LOGIN_FAILED", ERROR_MESSAGES["login_failed"]),
            "FORBIDDEN": ("FORBIDDEN", ERROR_MESSAGES.get("forbidden", "Forbidden")),
            "VALIDATION_ERROR": ("VALIDATION_ERROR", ERROR_MESSAGES.get("auth_validation_error", "Validation error")),
            "USER_NOT_FOUND": ("USER_NOT_FOUND", ERROR_MESSAGES.get("user_not_found", "User not found")),
        }
        code, message = map_simple.get(reason, ("UNHANDLED_ERROR", default_msg))

        self.set_header("Content-Type", HTTP_CONFIG["error_content_type"])
        self.finish({"error": {"code": code, "message": message}})

    def get_current_user(self):
        return self.current_user

    def on_finish(self):
        logger.info("%s %s -> %s", self.request.method, self.request.uri, self.get_status())


def validate_credentials_format(username: str, password: str) -> Optional[str]:
    """Validate username and password format."""
    if not username or not password:
        return ERROR_MESSAGES["auth_validation_error"]["credentials"]
    if not USERNAME_CONFIG["regex"].match(username):
        return ERROR_MESSAGES["auth_validation_error"]["username"]
    if not (PASSWORD_CONFIG["min_length"] <= len(password) <= PASSWORD_CONFIG["max_length"]):
        return ERROR_MESSAGES["auth_validation_error"]["password"]
    return None


def generate_jwt_token(user_id: str, username: str, role: str) -> Dict[str, Any]:
    """Generate JWT token for a user."""
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
    """Decorator to enforce JWT auth on a handler method."""
    @wraps(handler_method)
    async def wrapper(self: BaseHandler, *args, **kwargs):
        if not isinstance(self, BaseHandler):
            return await handler_method(self, *args, **kwargs)

        if not self.current_user:
            auth_header = self.request.headers.get("Authorization", "")
            if not auth_header.startswith("Bearer "):
                raise tornado.web.HTTPError(401, reason="MISSING_TOKEN")
            raise tornado.web.HTTPError(401, reason="INVALID_TOKEN")

        return await handler_method(self, *args, **kwargs)
    return wrapper


class RegisterHandler(BaseHandler):
    """Handle user registration."""
    async def post(self):
        data = self.json or {}
        username = data.get("username", "").strip().lower()
        password = data.get("password", "")

        validation_error = validate_credentials_format(username, password)
        if validation_error:
            raise tornado.web.HTTPError(400, reason="VALIDATION_ERROR")

        try:
            exists = await es_io(es.exists, index=ES_CONFIG["user_index"], id=username)
            if exists:
                raise tornado.web.HTTPError(409, reason="USERNAME_TAKEN")

            hashed_pw = await cpu_io(
                bcrypt.hashpw, password.encode(), bcrypt.gensalt(rounds=PASSWORD_CONFIG["bcrypt_rounds"])
            )
            hashed_pw = hashed_pw.decode("utf-8")

            user_doc = {
                "username": username,
                "password_hash": hashed_pw,
                "created_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                "is_active": True,
                "role": ES_CONFIG["default_role"],
            }

            resp = await es_io(
                es.index,
                index=ES_CONFIG["user_index"],
                id=username,
                op_type="create",
                document=user_doc,
                refresh="wait_for",
            )
            self.set_status(201)
            self.finish({"message": "User registered successfully", "username": username, "user_id": resp["_id"]})

        except ConflictError:
            raise tornado.web.HTTPError(409, reason="USERNAME_TAKEN")
        except tornado.web.HTTPError:
            raise
        except Exception:
            logger.exception("REGISTRATION_FAILED")
            self.send_error(500, reason="REGISTRATION_FAILED")


class LoginHandler(BaseHandler):
    """Handle user login and JWT generation."""
    async def post(self):
        data = self.json or {}
        username = data.get("username", "").strip().lower()
        password = data.get("password", "")

        if not username or not password:
            raise tornado.web.HTTPError(400, reason="VALIDATION_ERROR")

        try:
            resp = await es_io(es.get, index=ES_CONFIG["user_index"], id=username)
            user_doc = resp["_source"]
            if not user_doc.get("is_active", True):
                raise tornado.web.HTTPError(401, reason="INVALID_CREDENTIALS")

            stored_hash = user_doc.get("password_hash")
            if not stored_hash:
                raise tornado.web.HTTPError(401, reason="INVALID_CREDENTIALS")

            valid = await cpu_io(bcrypt.checkpw, password.encode(), stored_hash.encode())
            if not valid:
                raise tornado.web.HTTPError(401, reason="INVALID_CREDENTIALS")

            token_data = generate_jwt_token(username, username, user_doc.get("role", ES_CONFIG["default_role"]))
            self.finish({
                "token": token_data["token"],
                "token_type": "Bearer",
                "expires_in": token_data["expires_in"],
                "username": username
            })

        except tornado.web.HTTPError:
            raise
        except Exception:
            logger.exception("LOGIN_FAILED")
            self.send_error(500, reason="LOGIN_FAILED")
