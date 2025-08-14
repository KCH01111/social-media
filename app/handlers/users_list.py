import logging
from app.handlers.base_user_handler import BaseUserHandler
from services.users import public_user_view
from services.es import es
from services.es_io import es_io
from app.settings import PAGINATION_CONFIG, ERROR_MESSAGES, ES_CONFIG

logger = logging.getLogger(__name__)

class UsersListHandler(BaseUserHandler):
    """GET /users — list users with pagination and filters."""
    async def get(self):
        try:
            page = max(
                PAGINATION_CONFIG["default_page"],
                int(self.get_argument("page", str(PAGINATION_CONFIG["default_page"])) or PAGINATION_CONFIG["default_page"])
            )
            size = min(
                PAGINATION_CONFIG["max_page_size"],
                max(
                    PAGINATION_CONFIG["min_page_size"],
                    int(self.get_argument("size", str(PAGINATION_CONFIG["default_page_size"])) or PAGINATION_CONFIG["default_page_size"])
                )
            )
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
            items = [public_user_view(h["_source"]) | {"is_active": h["_source"].get("is_active", True)} for h in res["hits"]["hits"]]
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
