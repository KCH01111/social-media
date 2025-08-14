import logging
import bcrypt
import tornado.web
from elasticsearch import ConflictError
from app.handlers.base_handler import BaseHandler
from services.es import es
from services.es_io import es_io, cpu_io
from services.auth import validate_credentials_format, generate_jwt_token
from app.settings import PASSWORD_CONFIG, ES_CONFIG, ERROR_MESSAGES

logger = logging.getLogger(__name__)

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
                "created_at": self._utc_now(),
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

    def _utc_now(self):
        import datetime
        return datetime.datetime.now(datetime.timezone.utc).isoformat()

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
