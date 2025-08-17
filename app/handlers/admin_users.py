import datetime
import logging
from urllib.parse import unquote
import tornado.web
from elasticsearch import NotFoundError
from handlers.base_user_handler import BaseUserHandler
from services.users import is_admin
from services.es import es
from services.es_io import es_io
from services.auth import jwt_required
from settings import USER_ROLES, ERROR_MESSAGES, ES_CONFIG

logger = logging.getLogger(__name__)

class AdminUserHandler(BaseUserHandler):
    """PATCH/DELETE /admin/users/{username} — admin operations."""

    @jwt_required
    async def patch(self, username: str):
        if not await is_admin(self):
            raise tornado.web.HTTPError(403, reason="FORBIDDEN")

        username = unquote(username).strip().lower()
        if not username:
            raise tornado.web.HTTPError(400, reason="INVALID_USERNAME")

        data = self.json or {}
        updates = {}

        for field in ("display_name", "bio", "avatar_url", "email"):
            if field in data:
                updates[field] = data[field]

        if "role" in data:
            if data["role"] not in USER_ROLES:
                raise tornado.web.HTTPError(400, reason="VALIDATION_ERROR")
            updates["role"] = data["role"]

        if "is_active" in data:
            updates["is_active"] = bool(data["is_active"])

        if not updates:
            self.set_status(400)
            self.finish({"error": {"code": "NO_CHANGES", "message": ERROR_MESSAGES["no_changes"]}})
            return

        updates["updated_at"] = self._utc_now()
        try:
            await es_io(es.update, index=ES_CONFIG["user_index"], id=username, doc=updates, refresh="wait_for")
            self.finish({"message": "User updated", "updated_fields": list(updates.keys())})
        except NotFoundError:
            raise tornado.web.HTTPError(404, reason="USER_NOT_FOUND")
        except tornado.web.HTTPError:
            raise
        except Exception:
            logger.exception("UPDATE_ERROR")
            self.set_status(500)
            self.finish({"error": {"code": "UPDATE_ERROR", "message": ERROR_MESSAGES.get("update_error", "Could not update profile")}})

    @jwt_required
    async def delete(self, username: str):
        if not await is_admin(self):
            raise tornado.web.HTTPError(403, reason="FORBIDDEN")

        username = unquote(username).strip().lower()
        if not username:
            raise tornado.web.HTTPError(400, reason="INVALID_USERNAME")

        try:
            await es_io(
                es.update,
                index=ES_CONFIG["user_index"],
                id=username,
                doc={"is_active": False, "updated_at": self._utc_now()},
                refresh="wait_for",
            )
            self.finish({"message": "User deactivated"})
        except NotFoundError:
            raise tornado.web.HTTPError(404, reason="USER_NOT_FOUND")
        except tornado.web.HTTPError:
            raise
        except Exception:
            logger.exception("DELETE_ERROR")
            self.set_status(500)
            self.finish({"error": {"code": "DELETE_ERROR", "message": ERROR_MESSAGES.get("delete_error", "Could not deactivate account")}})

    def _utc_now(self):
        return datetime.datetime.now(datetime.timezone.utc).isoformat()
