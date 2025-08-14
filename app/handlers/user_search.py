import logging
from app.handlers.base_user_handler import BaseUserHandler
from services.users import public_user_view
from services.es import es
from services.es_io import es_io
from app.settings import PAGINATION_CONFIG, ERROR_MESSAGES, ES_CONFIG

logger = logging.getLogger(__name__)

class UserSearchHandler(BaseUserHandler):
    """GET /users/search?q=&page=&size= — search active users."""
    async def get(self):
        q = self.get_argument("q", "").strip()
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
            items = []
            for hit in res["hits"]["hits"]:
                u = public_user_view(hit["_source"])
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
