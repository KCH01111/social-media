import json
import datetime
import logging
from typing import Dict, Any, Optional, List
from urllib.parse import unquote

import tornado.web
from elasticsearch import NotFoundError

from services.es import es
from auth.handlers import BaseAuthHandler, jwt_required, get_current_user
from configurations import (
    USER_PROFILE_CONFIG,
    PAGINATION_CONFIG,
    USER_STATS_DEFAULTS,
    USER_ROLES,
    ERROR_MESSAGES,
    ES_CONFIG
)

logger = logging.getLogger(__name__)

def _valid_url(url: Optional[str]) -> bool:
    """Check if a given string is a valid URL based on USER_PROFILE_CONFIG['url_pattern'] regex."""
    return True if not url else bool(USER_PROFILE_CONFIG["url_pattern"].match(url))

def _public_user_view(src: Dict[str, Any]) -> Dict[str, Any]:
    """Return a sanitized public view of a user document from Elasticsearch."""
    return {
        "username": src.get("username"),
        "display_name": src.get("display_name", src.get("username")),
        "bio": src.get("bio", ""),
        "avatar_url": src.get("avatar_url"),
        "created_at": src.get("created_at"),
        "stats": src.get("stats", USER_STATS_DEFAULTS.copy())
    }

async def _is_admin(handler: tornado.web.RequestHandler) -> bool:
    """Check if the current user has admin privileges by looking up role in Elasticsearch."""
    try:
        doc = es.get(index=ES_CONFIG["user_index"], id=handler.current_username)["_source"]
        return doc.get("role", ES_CONFIG["default_role"]) == "admin"
    except Exception:
        return False

class BaseUserHandler(BaseAuthHandler):
    """Base user handler with extended CORS support for GET, PATCH, DELETE."""
    def set_default_headers(self):
        super().set_default_headers()
        self.set_header("Access-Control-Allow-Methods", "GET, PATCH, DELETE, OPTIONS")
    def options(self, *args, **kwargs):
        """Handle preflight OPTIONS request for CORS."""
        self.set_status(204); self.finish()

class UserDetailHandler(BaseUserHandler):
    """Handler for retrieving public details of a specific user by username."""
    async def get(self, username: str):
        username = unquote(username).strip().lower()
        if not username:
            self.write_error_response(400, "INVALID_USERNAME", ERROR_MESSAGES["invalid_username"]); return
        try:
            doc = es.get(index=ES_CONFIG["user_index"], id=username)["_source"]
            if not doc.get("is_active", True):
                self.write_error_response(404, "USER_NOT_FOUND", ERROR_MESSAGES["user_not_found"]); return
            self.write(_public_user_view(doc))
        except NotFoundError:
            self.write_error_response(404, "USER_NOT_FOUND", ERROR_MESSAGES["user_not_found"])
        except Exception as e:
            logger.error(f"/users/{username} error: {e}")
            self.write_error_response(500, "FETCH_ERROR", ERROR_MESSAGES["fetch_error"])

class MeHandler(BaseUserHandler):
    """Handler for viewing, updating, or deactivating the currently authenticated user's profile."""

    @jwt_required
    async def get(self):
        """Retrieve the current user's profile including private fields."""
        try:
            doc = es.get(index=ES_CONFIG["user_index"], id=self.current_username)["_source"]
            resp = _public_user_view(doc)
            resp.update({
                "email": doc.get("email"),
                "role": doc.get("role", ES_CONFIG["default_role"]),
                "is_active": doc.get("is_active", True),
                "updated_at": doc.get("updated_at")
            })
            self.write(resp)
        except NotFoundError:
            self.write_error_response(404, "USER_NOT_FOUND", ERROR_MESSAGES["user_not_found"])
        except Exception as e:
            logger.error(f"/users/me GET error: {e}")
            self.write_error_response(500, "FETCH_ERROR", ERROR_MESSAGES["fetch_error"])

    @jwt_required
    async def patch(self):
        """Update the current user's profile fields such as display_name, bio, avatar_url, and email."""
        data = self.parse_json_body()
        if data is None:
            self.write_error_response(400, "INVALID_JSON", ERROR_MESSAGES["invalid_json"]); return

        updates: Dict[str, Any] = {}
        errs: List[str] = []

        if "display_name" in data:
            val = data["display_name"]
            if not isinstance(val, str):
                errs.append("display_name must be a string")
            elif len(val.strip()) > USER_PROFILE_CONFIG["display_name_max_length"]:
                errs.append(ERROR_MESSAGES["validation_error"]["display_name"])
            else:
                updates["display_name"] = val.strip()

        if "bio" in data:
            val = data["bio"]
            if not isinstance(val, str):
                errs.append("bio must be a string")
            elif len(val) > USER_PROFILE_CONFIG["bio_max_length"]:
                errs.append(ERROR_MESSAGES["validation_error"]["bio"])
            else:
                updates["bio"] = val.strip()

        if "avatar_url" in data:
            val = data["avatar_url"]
            if val and not isinstance(val, str):
                errs.append("avatar_url must be a string")
            elif val and not _valid_url(val):
                errs.append(ERROR_MESSAGES["validation_error"]["avatar_url"])
            else:
                updates["avatar_url"] = val.strip() if val else None

        if "email" in data:
            val = data["email"]
            if val and not isinstance(val, str):
                errs.append("email must be a string")
            elif val and "@" not in val:
                errs.append(ERROR_MESSAGES["validation_error"]["email"])
            else:
                updates["email"] = val.lower().strip() if val else None

        if errs:
            self.write_error_response(400, "VALIDATION_ERROR", "; ".join(errs)); return
        if not updates:
            self.write_error_response(400, "NO_CHANGES", ERROR_MESSAGES["no_changes"]); return

        updates["updated_at"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
        try:
            es.update(index=ES_CONFIG["user_index"], id=self.current_username, doc=updates, refresh="wait_for")
            self.write({"message": "Profile updated", "updated_fields": list(updates.keys())})
        except Exception as e:
            logger.error(f"/users/me PATCH error: {e}")
            self.write_error_response(500, "UPDATE_ERROR", ERROR_MESSAGES["update_error"])

    @jwt_required
    async def delete(self):
        """Deactivate (soft delete) the current user's account."""
        try:
            es.update(
                index=ES_CONFIG["user_index"],
                id=self.current_username,
                doc={"is_active": False, "updated_at": datetime.datetime.now(datetime.timezone.utc).isoformat()},
                refresh="wait_for",
            )
            self.write({"message": "Account deactivated"})
        except NotFoundError:
            self.write_error_response(404, "USER_NOT_FOUND", ERROR_MESSAGES["user_not_found"])
        except Exception as e:
            logger.error(f"/users/me DELETE error: {e}")
            self.write_error_response(500, "DELETE_ERROR", ERROR_MESSAGES["delete_error"])

class UsersListHandler(BaseUserHandler):
    """Handler for listing all users with optional filters and pagination."""
    def set_default_headers(self):
        super().set_default_headers()
        self.set_header("Access-Control-Allow-Methods", "GET, OPTIONS")

    async def get(self):
        """List users with pagination, active filter, and optional search query."""
        page = max(PAGINATION_CONFIG["default_page"], 
                  int(self.get_argument("page", str(PAGINATION_CONFIG["default_page"])) or PAGINATION_CONFIG["default_page"]))
        size = min(PAGINATION_CONFIG["max_page_size"], 
                  max(PAGINATION_CONFIG["min_page_size"], 
                      int(self.get_argument("size", str(PAGINATION_CONFIG["default_page_size"])) or PAGINATION_CONFIG["default_page_size"])))
        active = self.get_argument("active", "true").lower()
        qtext = self.get_argument("q", "").strip()

        must = []
        if active in ("true", "false"):
            must.append({"term": {"is_active": active == "true"}})
        if qtext:
            must.append({"multi_match": {"query": qtext, "fields": ["username^2", "display_name"], "type": "best_fields"}})

        es_query = {"bool": {"must": must or [{"match_all": {}}]}}

        try:
            res = es.search(
                index=ES_CONFIG["user_index"],
                query=es_query,
                sort=[{"created_at": {"order": "desc"}}],
                from_=(page - 1) * size,
                size=size,
                _source=["username","display_name","bio","avatar_url","created_at","stats","is_active"]
            )
            items = [_public_user_view(h["_source"]) | {"is_active": h["_source"].get("is_active", True)} for h in res["hits"]["hits"]]
            total = res["hits"]["total"]["value"]
            total_pages = (total + size - 1) // size
            self.write({"users": items, "pagination": {"current_page": page, "page_size": size, "total_results": total, "total_pages": total_pages}})
        except Exception as e:
            logger.error(f"/users list error: {e}")
            self.write_error_response(500, "LIST_ERROR", "Could not list users")

class UserSearchHandler(BaseUserHandler):
    """Handler for searching active users by username or display_name."""
    def set_default_headers(self):
        super().set_default_headers()
        self.set_header("Access-Control-Allow-Methods", "GET, OPTIONS")

    async def get(self):
        """Search users using phrase prefix and fuzzy matching with pagination."""
        q = self.get_argument("q", "").strip()
        page = max(PAGINATION_CONFIG["default_page"], 
                  int(self.get_argument("page", str(PAGINATION_CONFIG["default_page"])) or PAGINATION_CONFIG["default_page"]))
        size = min(PAGINATION_CONFIG["max_page_size"], 
                  max(PAGINATION_CONFIG["min_page_size"], 
                      int(self.get_argument("size", str(PAGINATION_CONFIG["default_page_size"])) or PAGINATION_CONFIG["default_page_size"])))
        if not q:
            self.write_error_response(400, "MISSING_QUERY", ERROR_MESSAGES["missing_query"]); return
        if len(q) < 2:
            self.write_error_response(400, "QUERY_TOO_SHORT", ERROR_MESSAGES["query_too_short"]); return

        try:
            res = es.search(
                index=ES_CONFIG["user_index"],
                query={
                    "bool": {
                        "must": [{
                            "multi_match": {
                                "query": q,
                                "fields": ["username^2", "display_name"],
                                "type": "phrase_prefix",
                                "fuzziness": "AUTO"
                            }
                        }],
                        "filter": [{"term": {"is_active": True}}]
                    }
                },
                sort=[{"_score": {"order": "desc"}}, {"created_at": {"order": "desc"}}],
                from_=(page - 1) * size,
                size=size,
                _source=["username","display_name","bio","avatar_url","created_at","stats"]
            )
            items = []
            for hit in res["hits"]["hits"]:
                u = _public_user_view(hit["_source"])
                u["score"] = hit["_score"]
                items.append(u)

            total = res["hits"]["total"]["value"]
            total_pages = (total + size - 1) // size
            self.write({
                "users": items,
                "pagination": {
                    "current_page": page,
                    "total_pages": total_pages,
                    "total_results": total,
                    "page_size": size,
                    "has_next": page < total_pages,
                    "has_prev": page > 1
                },
                "query": q
            })
        except Exception as e:
            logger.error(f"/users/search error: {e}")
            self.write_error_response(500, "SEARCH_ERROR", ERROR_MESSAGES["search_error"])

class UserStatsHandler(BaseUserHandler):
    """Handler for retrieving a user's public and optionally private stats."""
    def set_default_headers(self):
        super().set_default_headers()
        self.set_header("Access-Control-Allow-Methods", "GET, OPTIONS")

    async def get(self, username: str):
        """Retrieve post/follow counts and, for self, private stats like profile views."""
        username = unquote(username).strip().lower()
        if not username:
            self.write_error_response(400, "INVALID_USERNAME", ERROR_MESSAGES["invalid_username"]); return
        try:
            u = es.get(index=ES_CONFIG["user_index"], id=username)["_source"]
        except NotFoundError:
            self.write_error_response(404, "USER_NOT_FOUND", ERROR_MESSAGES["user_not_found"]); return
        except Exception as e:
            logger.error(f"/users/{username}/stats fetch user error: {e}")
            self.write_error_response(500, "FETCH_ERROR", ERROR_MESSAGES["fetch_error"]); return

        stats = u.get("stats", USER_STATS_DEFAULTS.copy())

        try:
            cnt = es.count(index="posts", query={"term": {"author_id": username}})
            stats["posts_count"] = cnt["count"]
        except Exception:
            pass

        resp = {"username": username, "stats": stats}
        current = get_current_user(self)
        if current and current["username"] == username:
            resp["private_stats"] = {
                "profile_views": u.get("profile_views", 0),
                "last_active": u.get("last_active")
            }
        self.write(resp)

class AdminUserHandler(BaseUserHandler):
    """Handler for admin-level user management: update and deactivate accounts."""

    @jwt_required
    async def patch(self, username: str):
        """Allow admin to update user fields including role and activation status."""
        if not await _is_admin(self):
            self.write_error_response(403, "FORBIDDEN", ERROR_MESSAGES["forbidden"]); return

        username = unquote(username).strip().lower()
        if not username:
            self.write_error_response(400, "INVALID_USERNAME", ERROR_MESSAGES["invalid_username"]); return

        data = self.parse_json_body()
        if data is None:
            self.write_error_response(400, "INVALID_JSON", ERROR_MESSAGES["invalid_json"]); return

        updates: Dict[str, Any] = {}
        for field in ("display_name","bio","avatar_url","email"):
            if field in data: updates[field] = data[field]
        if "role" in data:
            if data["role"] not in USER_ROLES:
                self.write_error_response(400, "VALIDATION_ERROR", ERROR_MESSAGES["validation_error"]["role"]); return
            updates["role"] = data["role"]
        if "is_active" in data:
            updates["is_active"] = bool(data["is_active"])

        if not updates:
            self.write_error_response(400, "NO_CHANGES", ERROR_MESSAGES["no_changes"]); return

        updates["updated_at"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
        try:
            es.update(index=ES_CONFIG["user_index"], id=username, doc=updates, refresh="wait_for")
            self.write({"message": "User updated", "updated_fields": list(updates.keys())})
        except NotFoundError:
            self.write_error_response(404, "USER_NOT_FOUND", ERROR_MESSAGES["user_not_found"])
        except Exception as e:
            logger.error(f"/admin/users/{username} PATCH error: {e}")
            self.write_error_response(500, "UPDATE_ERROR", ERROR_MESSAGES["update_error"])

    @jwt_required
    async def delete(self, username: str):
        """Allow admin to deactivate (soft delete) a user account."""
        if not await _is_admin(self):
            self.write_error_response(403, "FORBIDDEN", ERROR_MESSAGES["forbidden"]); return

        username = unquote(username).strip().lower()
        if not username:
            self.write_error_response(400, "INVALID_USERNAME", ERROR_MESSAGES["invalid_username"]); return

        try:
            es.update(
                index=ES_CONFIG["user_index"],
                id=username,
                doc={"is_active": False, "updated_at": datetime.datetime.now(datetime.timezone.utc).isoformat()},
                refresh="wait_for"
            )
            self.write({"message": "User deactivated"})
        except NotFoundError:
            self.write_error_response(404, "USER_NOT_FOUND", ERROR_MESSAGES["user_not_found"])
        except Exception as e:
            logger.error(f"/admin/users/{username} DELETE error: {e}")
            self.write_error_response(500, "DELETE_ERROR", ERROR_MESSAGES["delete_error"])
