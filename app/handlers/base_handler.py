import logging
import jwt
import tornado.web
from tornado.escape import json_decode
from typing import Optional, Dict, Any
from app.settings import HTTP_CONFIG, ERROR_MESSAGES, JWT_SECRET, JWT_CONFIG, ES_CONFIG

logger = logging.getLogger(__name__)

class BaseHandler(tornado.web.RequestHandler):
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
