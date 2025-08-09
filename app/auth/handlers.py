import os
import json
import logging
import bcrypt
import jwt
import datetime

import tornado.web
from tornado.ioloop import IOLoop
from typing import Dict, Any, Optional
from functools import wraps

from services.es import es
from elasticsearch import ConflictError
from configurations import (
    JWT_SECRET,
    JWT_CONFIG,
    PASSWORD_CONFIG,
    USERNAME_CONFIG,
    ES_CONFIG,
    HTTP_CONFIG,
    ERROR_MESSAGES
)

logger = logging.getLogger(__name__)

class BaseAuthHandler(tornado.web.RequestHandler):
    """Base handler with common authentication utilities"""

    def set_default_headers(self):
        """Set CORS and security headers."""
        for header, value in HTTP_CONFIG["default_headers"].items():
            self.set_header(header, value)

    def write_error_response(self, status_code: int, error_code: str, message: str) -> None:
        """Send standardized JSON error response."""
        self.set_status(status_code)
        self.write({
            "error": {
                "code": error_code,
                "message": message
            }
        })

    def parse_json_body(self) -> Optional[Dict[str, Any]]:
        """Parse request body as JSON"""
        try:
            return json.loads(self.request.body.decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError) as e:
            logger.warning(f"Invalid JSON in request: {e}")
            return None

    def validate_credentials_format(self, username: str, password: str) -> Optional[str]:
        """Validate username/password. Return error message if invalid."""
        if not username or not password:
            return ERROR_MESSAGES["validation_error"]["credentials"]
        if not USERNAME_CONFIG["regex"].match(username):
            return ERROR_MESSAGES["validation_error"]["username"]
        if not (PASSWORD_CONFIG["min_length"] <= len(password) <= PASSWORD_CONFIG["max_length"]):
            return ERROR_MESSAGES["validation_error"]["password"]
        return None

class RegisterHandler(BaseAuthHandler):
    """Handle user registration."""

    async def post(self):
        data = self.parse_json_body()
        if data is None:
            self.write_error_response(400, "INVALID_JSON", ERROR_MESSAGES["invalid_json"])
            return

        username = data.get("username", "").strip().lower()
        password = data.get("password", "")

        validation_error = self.validate_credentials_format(username, password)
        if validation_error:
            self.write_error_response(400, "VALIDATION_ERROR", validation_error)
            return

        try:
            exists = await IOLoop.current().run_in_executor(
                None,
                lambda: es.exists(index=ES_CONFIG["user_index"], id=username)
            )
            if exists:
                self.write_error_response(409, "USERNAME_TAKEN", ERROR_MESSAGES["username_taken"])
                return

            user_id = await self._create_user(username, password)
            self.set_status(201)
            self.write({
                "message": "User registered successfully",
                "username": username,
                "user_id": user_id
            })

        except Exception as e:
            logger.error(f"Registration error for {username}: {e}")
            self.write_error_response(500, "REGISTRATION_FAILED", ERROR_MESSAGES["registration_failed"])

    async def _create_user(self, username: str, password: str) -> str:
        """Create new user document (username used as ES ID)."""
        loop = IOLoop.current()
        hashed_pw = await loop.run_in_executor(
            None,
            lambda: bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=PASSWORD_CONFIG["bcrypt_rounds"])).decode("utf-8")
        )

        user_doc = {
            "username": username,
            "password_hash": hashed_pw,
            "created_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "is_active": True,
            "role": ES_CONFIG["default_role"]
        }

        try:
            resp = es.index(
                index=ES_CONFIG["user_index"],
                id=username,
                op_type="create",           
                document=user_doc,
                refresh="wait_for"
            )
            return resp["_id"]
        except ConflictError:
            raise Exception("USERNAME_TAKEN")
        except Exception as e:
            logger.error(f"Database error creating user: {e}")
            raise

class LoginHandler(BaseAuthHandler):
    """Handle user login and JWT generation."""

    async def post(self):
        data = self.parse_json_body()
        if data is None:
            self.write_error_response(400, "INVALID_JSON", ERROR_MESSAGES["invalid_json"])
            return

        username = data.get("username", "").strip().lower()
        password = data.get("password", "")

        if not username or not password:
            self.write_error_response(401, "INVALID_CREDENTIALS", ERROR_MESSAGES["invalid_credentials"])
            return

        try:
            user_data = await self._authenticate_user(username, password)
            if user_data is None:
                self.write_error_response(401, "INVALID_CREDENTIALS", ERROR_MESSAGES["invalid_credentials"])
                return

            token_data = self._generate_jwt_token(user_data["user_id"], username)
            self.write({
                "token": token_data["token"],
                "token_type": "Bearer",
                "expires_in": token_data["expires_in"],
                "username": username
            })

        except Exception as e:
            logger.error(f"Login error for {username}: {e}")
            self.write_error_response(500, "LOGIN_FAILED", ERROR_MESSAGES["login_failed"])
            return

    async def _authenticate_user(self, username: str, password: str) -> Optional[Dict[str, Any]]:
        """Verify credentials against ES."""
        try:
            resp = es.get(index=ES_CONFIG["user_index"], id=username)
            user_doc = resp["_source"]
            if not user_doc.get("is_active", True):
                return None

            stored_hash = user_doc.get("password_hash")
            if not stored_hash:
                return None

            valid = await IOLoop.current().run_in_executor(
                None,
                lambda: bcrypt.checkpw(password.encode(), stored_hash.encode())
            )
            if valid:
                return {"user_id": username, "username": username, "role": user_doc.get("role", ES_CONFIG["default_role"])}
            return None

        except Exception as e:
            logger.error(f"Authentication DB error for {username}: {e}")
            raise

    def _generate_jwt_token(self, user_id: str, username: str) -> Dict[str, Any]:
        """Create signed JWT."""
        now = datetime.datetime.now(datetime.timezone.utc)
        expiry = now + datetime.timedelta(minutes=JWT_CONFIG["exp_minutes"])
        payload = {
            "sub": user_id,
            "username": username,
            "iss": JWT_CONFIG["issuer"],
            "iat": int(now.timestamp()),
            "exp": int(expiry.timestamp())
        }
        token = jwt.encode(payload, JWT_SECRET, algorithm=JWT_CONFIG["algorithm"])
        return {"token": token, "expires_in": JWT_CONFIG["exp_minutes"] * 60}

def verify_jwt_token(token: str) -> Optional[Dict[str, Any]]:
    """Verify JWT and return payload or None."""
    try:
        return jwt.decode(
            token,
            JWT_SECRET,
            algorithms=[JWT_CONFIG["algorithm"]],
            options={
                "require": JWT_CONFIG["required_claims"],
                "verify_exp": True,
                "verify_iat": True
            },
            issuer=JWT_CONFIG["issuer"]
        )
    except jwt.ExpiredSignatureError:
        logger.warning("JWT token expired")
    except jwt.InvalidIssuerError:
        logger.warning("JWT token has invalid issuer")
    except jwt.InvalidTokenError as e:
        logger.warning(f"Invalid JWT token: {e}")
    return None

def jwt_required(handler_method):
    """Tornado decorator to enforce JWT auth on a handler method."""
    @wraps(handler_method)
    async def wrapper(self, *args, **kwargs):
        auth_header = self.request.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            self.write_error_response(401, "MISSING_TOKEN", ERROR_MESSAGES["missing_token"])
            return

        token = auth_header.split(" ", 1)[1]
        payload = verify_jwt_token(token)
        if payload is None:
            self.write_error_response(401, "INVALID_TOKEN", ERROR_MESSAGES["invalid_token"])
            return

        self.current_user_id = payload["sub"]
        self.current_username = payload["username"]
        return await handler_method(self, *args, **kwargs)
    return wrapper

def get_current_user(request_handler) -> Optional[Dict[str, str]]:
    if hasattr(request_handler, "current_user_id"):
        return {
            "user_id": request_handler.current_user_id,
            "username": request_handler.current_username
        }
    return None