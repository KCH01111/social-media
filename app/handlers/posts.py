import logging
import datetime
from typing import Dict, Any, Optional, List

import tornado.web
from elasticsearch import NotFoundError

from services.es import es
from app.handlers.auth import BaseHandler, jwt_required, es_io
from app.settings import (
    PAGINATION_CONFIG,
    ERROR_MESSAGES,
    USER_PROFILE_CONFIG,
    POSTS_INDEX,
    TEXT_MAX_LEN,
    TAGS_MAX,
)

logger = logging.getLogger(__name__)


def _now_iso() -> str:
    """UTC timestamp ISO8601."""
    return datetime.datetime.now(datetime.timezone.utc).isoformat()

def _valid_url(url: Optional[str]) -> bool:
    """Allow empty or regex-valid URL."""
    return True if not url else bool(USER_PROFILE_CONFIG["url_pattern"].match(url))

def _normalize_tags(tags_val) -> List[str]:
    """Accept list[str] or comma string; return cleaned list (<= TAGS_MAX)."""
    if tags_val is None:
        return []
    raw = tags_val if isinstance(tags_val, list) else str(tags_val).split(",")
    out: List[str] = []
    for t in raw:
        s = str(t).strip().lower()
        if s:
            out.append(s)
        if len(out) >= TAGS_MAX:
            break
    return out

def _sanitize_post(src: Dict[str, Any]) -> Dict[str, Any]:
    """Public-facing post projection."""
    return {
        "id": src.get("id"),
        "author_id": src.get("author_id"),
        "text": src.get("text", ""),
        "image_url": src.get("image_url"),
        "tags": src.get("tags", []),
        "likes_count": src.get("likes_count", 0),
        "is_deleted": src.get("is_deleted", False),
        "created_at": src.get("created_at"),
        "updated_at": src.get("updated_at"),
    }


class CreatePostHandler(BaseHandler):
    """POST /posts — create a post (auth)."""

    @jwt_required
    async def post(self):
        data = self.json or {}
        text = (data.get("text") or "").strip()
        image_url = data.get("image_url") or None
        tags = _normalize_tags(data.get("tags"))

        if not text or len(text) > TEXT_MAX_LEN:
            raise tornado.web.HTTPError(400, reason="VALIDATION_ERROR")
        if image_url and not _valid_url(image_url):
            raise tornado.web.HTTPError(400, reason="VALIDATION_ERROR")

        doc = {
            "author_id": self.current_user["username"],
            "text": text,
            "image_url": image_url,
            "tags": tags,
            "likes_count": 0,
            "is_deleted": False,
            "created_at": _now_iso(),
            "updated_at": None,
        }

        try:
            resp = await es_io(es.index, index=POSTS_INDEX, document=doc, refresh="wait_for")
            post_id = resp["_id"]
            await es_io(es.update, index=POSTS_INDEX, id=post_id, doc={"id": post_id}, refresh="wait_for")
            created = await es_io(es.get, index=POSTS_INDEX, id=post_id)
            self.set_status(201)
            self.finish(_sanitize_post(created["_source"]))
        except Exception:
            logger.exception("POST_CREATE_ERROR")
            self.set_status(500)
            self.finish({"error": {"code": "UPDATE_ERROR", "message": ERROR_MESSAGES.get("update_error", "Could not update profile")}})


class PostDetailHandler(BaseHandler):
    """GET /posts/{id} — fetch one (not deleted)."""

    async def get(self, post_id: str):
        try:
            res = await es_io(es.get, index=POSTS_INDEX, id=post_id)
            src = res["_source"]
            if src.get("is_deleted"):
                self.set_status(404)
                self.finish({"error": {"code": "POST_NOT_FOUND", "message": "Post not found"}})
                return
            self.finish(_sanitize_post(src))
        except NotFoundError:
            self.set_status(404)
            self.finish({"error": {"code": "POST_NOT_FOUND", "message": "Post not found"}})
        except tornado.web.HTTPError:
            raise
        except Exception:
            logger.exception("POST_FETCH_ERROR")
            self.set_status(500)
            self.finish({"error": {"code": "FETCH_ERROR", "message": ERROR_MESSAGES.get("fetch_error", "Could not retrieve user profile")}})


class UpdatePostHandler(BaseHandler):
    """PATCH /posts/{id} — update text/image_url/tags (author only)."""

    @jwt_required
    async def patch(self, post_id: str):
        data = self.json or {}
        updates: Dict[str, Any] = {}
        errs: List[str] = []

        if "text" in data:
            text = (data.get("text") or "").strip()
            if not text or len(text) > TEXT_MAX_LEN:
                errs.append("text invalid")
            else:
                updates["text"] = text

        if "image_url" in data:
            image_url = data.get("image_url")
            if image_url and not _valid_url(image_url):
                errs.append("image_url invalid")
            else:
                updates["image_url"] = image_url or None

        if "tags" in data:
            updates["tags"] = _normalize_tags(data.get("tags"))

        if errs:
            raise tornado.web.HTTPError(400, reason="VALIDATION_ERROR")
        if not updates:
            self.set_status(400)
            self.finish({"error": {"code": "NO_CHANGES", "message": ERROR_MESSAGES["no_changes"]}})
            return

        try:
            cur = await es_io(es.get, index=POSTS_INDEX, id=post_id)
            src = cur["_source"]
            if src.get("is_deleted"):
                self.set_status(404)
                self.finish({"error": {"code": "POST_NOT_FOUND", "message": "Post not found"}})
                return
            if src.get("author_id") != self.current_user.get("username"):
                raise tornado.web.HTTPError(403, reason="FORBIDDEN")

            updates["updated_at"] = _now_iso()
            await es_io(es.update, index=POSTS_INDEX, id=post_id, doc=updates, refresh="wait_for")
            newdoc = await es_io(es.get, index=POSTS_INDEX, id=post_id)
            self.finish(_sanitize_post(newdoc["_source"]))
        except NotFoundError:
            self.set_status(404)
            self.finish({"error": {"code": "POST_NOT_FOUND", "message": "Post not found"}})
        except tornado.web.HTTPError:
            raise
        except Exception:
            logger.exception("POST_UPDATE_ERROR")
            self.set_status(500)
            self.finish({"error": {"code": "UPDATE_ERROR", "message": ERROR_MESSAGES.get("update_error", "Could not update profile")}})


class DeletePostHandler(BaseHandler):
    """DELETE /posts/{id} — soft delete (author or admin)."""

    @jwt_required
    async def delete(self, post_id: str):
        try:
            cur = await es_io(es.get, index=POSTS_INDEX, id=post_id)
            src = cur["_source"]
            if src.get("is_deleted"):
                self.set_status(404)
                self.finish({"error": {"code": "POST_NOT_FOUND", "message": "Post not found"}})
                return

            is_author = src.get("author_id") == self.current_user.get("username")
            is_admin = self.current_user.get("role") == "admin"
            if not (is_author or is_admin):
                raise tornado.web.HTTPError(403, reason="FORBIDDEN")

            await es_io(
                es.update,
                index=POSTS_INDEX,
                id=post_id,
                doc={"is_deleted": True, "updated_at": _now_iso()},
                refresh="wait_for",
            )
            self.finish({"message": "Post deleted"})
        except NotFoundError:
            self.set_status(404)
            self.finish({"error": {"code": "POST_NOT_FOUND", "message": "Post not found"}})
        except tornado.web.HTTPError:
            raise
        except Exception:
            logger.exception("POST_DELETE_ERROR")
            self.set_status(500)
            self.finish({"error": {"code": "DELETE_ERROR", "message": ERROR_MESSAGES.get("delete_error", "Could not deactivate account")}})


class PostsListHandler(BaseHandler):
    """GET /posts?author=&page=&size= — list non-deleted posts (newest first)."""

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

        author = (self.get_argument("author", "") or "").strip().lower()

        must: List[Dict[str, Any]] = [{"term": {"is_deleted": False}}]
        if author:
            must.append({"term": {"author_id": author}})

        query = {"bool": {"must": must}}

        try:
            res = await es_io(
                es.search,
                index=POSTS_INDEX,
                query=query,
                sort=[{"created_at": {"order": "desc"}}],
                from_=(page - 1) * size,
                size=size,
                _source=["id", "author_id", "text", "image_url", "tags", "likes_count", "is_deleted", "created_at", "updated_at"],
            )
            hits = res["hits"]["hits"]
            items = [_sanitize_post(h["_source"]) for h in hits]
            total = res["hits"]["total"]["value"]
            total_pages = (total + size - 1) // size

            self.finish({
                "posts": items,
                "pagination": {
                    "current_page": page,
                    "page_size": size,
                    "total_results": total,
                    "total_pages": total_pages,
                }
            })
        except Exception:
            logger.exception("POST_LIST_ERROR")
            self.set_status(500)
            self.finish({"error": {"code": "FETCH_ERROR", "message": ERROR_MESSAGES.get("fetch_error", "Could not retrieve user profile")}})


class PostsSearchHandler(BaseHandler):
    """GET /posts/search?q=&page=&size= — search text in non-deleted posts."""

    async def get(self):
        q = (self.get_argument("q", "") or "").strip()
        if not q:
            self.set_status(400)
            self.finish({"error": {"code": "MISSING_QUERY", "message": ERROR_MESSAGES["missing_query"]}})
            return
        if len(q) < 2:
            self.set_status(400)
            self.finish({"error": {"code": "QUERY_TOO_SHORT", "message": ERROR_MESSAGES["query_too_short"]}})
            return

        try:
            page = max(PAGINATION_CONFIG["default_page"],
                       int(self.get_argument("page", str(PAGINATION_CONFIG["default_page"])) or PAGINATION_CONFIG["default_page"]))
            size = min(PAGINATION_CONFIG["max_page_size"],
                       max(PAGINATION_CONFIG["min_page_size"],
                           int(self.get_argument("size", str(PAGINATION_CONFIG["default_page_size"])) or PAGINATION_CONFIG["default_page_size"])))
        except ValueError:
            page = PAGINATION_CONFIG["default_page"]
            size = PAGINATION_CONFIG["default_page_size"]

        query = {
            "bool": {
                "must": [
                    {"match": {"text": {"query": q, "operator": "and"}}},
                    {"term": {"is_deleted": False}},
                ]
            }
        }

        try:
            res = await es_io(
                es.search,
                index=POSTS_INDEX,
                query=query,
                sort=[{"_score": {"order": "desc"}}, {"created_at": {"order": "desc"}}],
                from_=(page - 1) * size,
                size=size,
                _source=["id", "author_id", "text", "image_url", "tags", "likes_count", "is_deleted", "created_at", "updated_at"],
            )
            hits = res["hits"]["hits"]
            items: List[Dict[str, Any]] = []
            for h in hits:
                p = _sanitize_post(h["_source"])
                p["score"] = h["_score"]
                items.append(p)

            total = res["hits"]["total"]["value"]
            total_pages = (total + size - 1) // size
            self.finish({
                "posts": items,
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
            logger.exception("POST_SEARCH_ERROR")
            self.set_status(500)
            self.finish({"error": {"code": "SEARCH_ERROR", "message": ERROR_MESSAGES.get("search_error", "Could not perform user search")}})
