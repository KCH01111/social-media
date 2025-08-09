import logging
import datetime
from typing import Dict, Any, Optional, List
from urllib.parse import unquote

import tornado.web
from elasticsearch import NotFoundError

from services.es import es
from app.handlers.auth import BaseHandler, jwt_required, es_io
from app.settings import (
    USER_PROFILE_CONFIG,
    PAGINATION_CONFIG,
    USER_STATS_DEFAULTS,
    USER_ROLES,
    ERROR_MESSAGES,
    ES_CONFIG,
)

logger = logging.getLogger(__name__)


def _valid_url(url: Optional[str]) -> bool:
    """Return True for empty or valid URL per regex."""
    return True if not url else bool(USER_PROFILE_CONFIG["url_pattern"].match(url))

def _public_user_view(src: Dict[str, Any]) -> Dict[str, Any]:
    """Project a user document into a public view."""
    return {
        "username": src.get("username"),
        "display_name": src.get("display_name", src.get("username")),
        "bio": src.get("bio", ""),
        "avatar_url": src.get("avatar_url"),
        "created_at": src.get("created_at"),
        "stats": src.get("stats", USER_STATS_DEFAULTS.copy()),
    }

async def _is_admin(handler: BaseHandler) -> bool:
    """Check if current user is admin."""
    try:
        doc = (await es_io(es.get, index=ES_CONFIG["user_index"], id=handler.current_user["username"]))["_source"]
        return doc.get("role", ES_CONFIG["default_role"]) == "admin"
    except Exception:
        return False


class BaseUserHandler(BaseHandler):
    """Base user handler with extended CORS methods."""
    def set_default_headers(self):
        super().set_default_headers()
        self.set_header("Access-Control-Allow-Methods", "GET, POST, PATCH, DELETE, OPTIONS")


class UserDetailHandler(BaseUserHandler):
    """GET /users/{username} — public profile."""
    async def get(self, username: str):
        username = unquote(username).strip().lower()
        if not username:
            raise tornado.web.HTTPError(400, reason="INVALID_USERNAME")
        try:
            doc = (await es_io(es.get, index=ES_CONFIG["user_index"], id=username))["_source"]
            if not doc.get("is_active", True):
                raise tornado.web.HTTPError(404, reason="USER_NOT_FOUND")
            self.finish(_public_user_view(doc))
        except NotFoundError:
            raise tornado.web.HTTPError(404, reason="USER_NOT_FOUND")
        except tornado.web.HTTPError:
            raise
        except Exception:
            logger.exception("FETCH_ERROR")
            self.set_status(500)
            self.finish({"error": {"code": "FETCH_ERROR", "message": ERROR_MESSAGES.get("fetch_error", "Could not retrieve user profile")}})


class MeHandler(BaseUserHandler):
    """GET/PATCH/DELETE /users/me — current user profile."""

    @jwt_required
    async def get(self):
        try:
            doc = (await es_io(es.get, index=ES_CONFIG["user_index"], id=self.current_user["username"]))["_source"]
            resp = _public_user_view(doc)
            resp.update({
                "email": doc.get("email"),
                "role": doc.get("role", ES_CONFIG["default_role"]),
                "is_active": doc.get("is_active", True),
                "updated_at": doc.get("updated_at"),
            })
            self.finish(resp)
        except NotFoundError:
            raise tornado.web.HTTPError(404, reason="USER_NOT_FOUND")
        except tornado.web.HTTPError:
            raise
        except Exception:
            logger.exception("FETCH_ERROR")
            self.set_status(500)
            self.finish({"error": {"code": "FETCH_ERROR", "message": ERROR_MESSAGES.get("fetch_error", "Could not retrieve user profile")}})

    @jwt_required
    async def patch(self):
        """Update display_name, bio, avatar_url, email."""
        data = self.json or {}
        updates: Dict[str, Any] = {}
        errs: List[str] = []

        if "display_name" in data:
            val = data["display_name"]
            if not isinstance(val, str):
                errs.append("display_name must be a string")
            elif len(val.strip()) > USER_PROFILE_CONFIG["display_name_max_length"]:
                errs.append(ERROR_MESSAGES["profile_validation_error"]["display_name"])
            else:
                updates["display_name"] = val.strip()

        if "bio" in data:
            val = data["bio"]
            if not isinstance(val, str):
                errs.append("bio must be a string")
            elif len(val) > USER_PROFILE_CONFIG["bio_max_length"]:
                errs.append(ERROR_MESSAGES["profile_validation_error"]["bio"])
            else:
                updates["bio"] = val.strip()

        if "avatar_url" in data:
            val = data["avatar_url"]
            if val and not isinstance(val, str):
                errs.append("avatar_url must be a string")
            elif val and not _valid_url(val):
                errs.append(ERROR_MESSAGES["profile_validation_error"]["avatar_url"])
            else:
                updates["avatar_url"] = val.strip() if val else None

        if "email" in data:
            val = data["email"]
            if val and not isinstance(val, str):
                errs.append("email must be a string")
            elif val and "@" not in val:
                errs.append(ERROR_MESSAGES["profile_validation_error"]["email"])
            else:
                updates["email"] = val.lower().strip() if val else None

        if errs:
            raise tornado.web.HTTPError(400, reason="VALIDATION_ERROR")
        if not updates:
            self.set_status(400)
            self.finish({"error": {"code": "NO_CHANGES", "message": ERROR_MESSAGES["no_changes"]}})
            return

        updates["updated_at"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
        try:
            await es_io(
                es.update,
                index=ES_CONFIG["user_index"],
                id=self.current_user["username"],
                doc=updates,
                refresh="wait_for",
            )
            self.finish({"message": "Profile updated", "updated_fields": list(updates.keys())})
        except Exception:
            logger.exception("UPDATE_ERROR")
            self.set_status(500)
            self.finish({"error": {"code": "UPDATE_ERROR", "message": ERROR_MESSAGES.get("update_error", "Could not update profile")}})

    @jwt_required
    async def delete(self):
        """Deactivate own account (soft delete)."""
        try:
            await es_io(
                es.update,
                index=ES_CONFIG["user_index"],
                id=self.current_user["username"],
                doc={"is_active": False, "updated_at": datetime.datetime.now(datetime.timezone.utc).isoformat()},
                refresh="wait_for",
            )
            self.finish({"message": "Account deactivated"})
        except NotFoundError:
            raise tornado.web.HTTPError(404, reason="USER_NOT_FOUND")
        except tornado.web.HTTPError:
            raise
        except Exception:
            logger.exception("DELETE_ERROR")
            self.set_status(500)
            self.finish({"error": {"code": "DELETE_ERROR", "message": ERROR_MESSAGES.get("delete_error", "Could not deactivate account")}})


class UsersListHandler(BaseUserHandler):
    """GET /users — list users with pagination and filters."""
    async def get(self):
        try:
            page = max(PAGINATION_CONFIG["default_page"],
                       int(self.get_argument("page", str(PAGINATION_CONFIG["default_page"])) or PAGINATION_CONFIG["default_page"]))
            size = min(PAGINATION_CONFIG["max_page_size"],
                       max(PAGINATION_CONFIG["min_page_size"],
                           int(self.get_argument("size", str(PAGINATION_CONFIG["default_page_size"])) or PAGINATION_CONFIG["default_page_size"])))
        except ValueError:
            page = PAGINATION_CONFIG["default_page"]
            size = PAGINATION_CONFIG["default_page_size"]

        active = self.get_argument("active", "true").lower()
        qtext = self.get_argument("q", "").strip()

        must = []
        if active in ("true", "false"):
            must.append({"term": {"is_active": active == "true"}})
        if qtext:
            must.append({"multi_match": {"query": qtext, "fields": ["username^2", "display_name"], "type": "best_fields"}})

        es_query = {"bool": {"must": must or [{"match_all": {}}]}}

        try:
            res = await es_io(
                es.search,
                index=ES_CONFIG["user_index"],
                query=es_query,
                sort=[{"created_at": {"order": "desc"}}],
                from_=(page - 1) * size,
                size=size,
                _source=["username","display_name","bio","avatar_url","created_at","stats","is_active"],
            )
            items = [_public_user_view(h["_source"]) | {"is_active": h["_source"].get("is_active", True)} for h in res["hits"]["hits"]]
            total = res["hits"]["total"]["value"]
            total_pages = (total + size - 1) // size
            self.finish({
                "users": items,
                "pagination": {"current_page": page, "page_size": size, "total_results": total, "total_pages": total_pages}
            })
        except Exception:
            logger.exception("LIST_ERROR")
            self.set_status(500)
            self.finish({"error": {"code": "FETCH_ERROR", "message": ERROR_MESSAGES.get("fetch_error", "Could not retrieve user profile")}})


class UserSearchHandler(BaseUserHandler):
    """GET /users/search?q=&page=&size= — search active users."""
    async def get(self):
        q = self.get_argument("q", "").strip()
        try:
            page = max(PAGINATION_CONFIG["default_page"],
                       int(self.get_argument("page", str(PAGINATION_CONFIG["default_page"])) or PAGINATION_CONFIG["default_page"]))
            size = min(PAGINATION_CONFIG["max_page_size"],
                       max(PAGINATION_CONFIG["min_page_size"],
                           int(self.get_argument("size", str(PAGINATION_CONFIG["default_page_size"])) or PAGINATION_CONFIG["default_page_size"])))
        except ValueError:
            page = PAGINATION_CONFIG["default_page"]
            size = PAGINATION_CONFIG["default_page_size"]

        if not q:
            self.set_status(400)
            self.finish({"error": {"code": "MISSING_QUERY", "message": ERROR_MESSAGES["missing_query"]}})
            return
        if len(q) < 2:
            self.set_status(400)
            self.finish({"error": {"code": "QUERY_TOO_SHORT", "message": ERROR_MESSAGES["query_too_short"]}})
            return

        try:
            res = await es_io(
                es.search,
                index=ES_CONFIG["user_index"],
                query={
                    "bool": {
                        "must": [{
                            "multi_match": {
                                "query": q,
                                "fields": ["username^2", "display_name"],
                                "type": "phrase_prefix",
                                "fuzziness": "AUTO",
                            }
                        }],
                        "filter": [{"term": {"is_active": True}}],
                    }
                },
                sort=[{"_score": {"order": "desc"}}, {"created_at": {"order": "desc"}}],
                from_=(page - 1) * size,
                size=size,
                _source=["username","display_name","bio","avatar_url","created_at","stats"],
            )
            items: List[Dict[str, Any]] = []
            for hit in res["hits"]["hits"]:
                u = _public_user_view(hit["_source"])
                u["score"] = hit["_score"]
                items.append(u)

            total = res["hits"]["total"]["value"]
            total_pages = (total + size - 1) // size
            self.finish({
                "users": items,
                "pagination": {
                    "current_page": page,
                    "total_pages": total_pages,
                    "total_results": total,
                    "page_size": size,
                    "has_next": page < total_pages,
                    "has_prev": page > 1,
                },
                "query": q,
            })
        except Exception:
            logger.exception("SEARCH_ERROR")
            self.set_status(500)
            self.finish({"error": {"code": "SEARCH_ERROR", "message": ERROR_MESSAGES.get("search_error", "Could not perform user search")}})


class UserStatsHandler(BaseUserHandler):
    """GET /users/{username}/stats — public stats; private fields for self."""
    async def get(self, username: str):
        username = unquote(username).strip().lower()
        if not username:
            raise tornado.web.HTTPError(400, reason="INVALID_USERNAME")
        try:
            u = (await es_io(es.get, index=ES_CONFIG["user_index"], id=username))["_source"]
        except NotFoundError:
            raise tornado.web.HTTPError(404, reason="USER_NOT_FOUND")
        except tornado.web.HTTPError:
            raise
        except Exception:
            logger.exception("FETCH_ERROR")
            self.set_status(500)
            self.finish({"error": {"code": "FETCH_ERROR", "message": ERROR_MESSAGES.get("fetch_error", "Could not retrieve user profile")}})
            return

        stats = u.get("stats", USER_STATS_DEFAULTS.copy())
        try:
            cnt = await es_io(es.count, index="posts", query={"term": {"author_id": username}})
            stats["posts_count"] = cnt["count"]
        except Exception:
            pass

        resp = {"username": username, "stats": stats}
        if self.current_user and self.current_user["username"] == username:
            resp["private_stats"] = {
                "profile_views": u.get("profile_views", 0),
                "last_active": u.get("last_active"),
            }
        self.finish(resp)


class AdminUserHandler(BaseUserHandler):
    """PATCH/DELETE /admin/users/{username} — admin operations."""

    @jwt_required
    async def patch(self, username: str):
        if not await _is_admin(self):
            raise tornado.web.HTTPError(403, reason="FORBIDDEN")

        username = unquote(username).strip().lower()
        if not username:
            raise tornado.web.HTTPError(400, reason="INVALID_USERNAME")

        data = self.json or {}
        updates: Dict[str, Any] = {}

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

        updates["updated_at"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
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
        if not await _is_admin(self):
            raise tornado.web.HTTPError(403, reason="FORBIDDEN")

        username = unquote(username).strip().lower()
        if not username:
            raise tornado.web.HTTPError(400, reason="INVALID_USERNAME")

        try:
            await es_io(
                es.update,
                index=ES_CONFIG["user_index"],
                id=username,
                doc={"is_active": False, "updated_at": datetime.datetime.now(datetime.timezone.utc).isoformat()},
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
