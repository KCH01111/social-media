import logging
from urllib.parse import unquote
from handlers.base_user_handler import BaseUserHandler
from services.users import public_user_view
from services.es import es
from services.es_io import es_io
from settings import PAGINATION_CONFIG, ERROR_MESSAGES, ES_CONFIG

logger = logging.getLogger(__name__)

class UsersListHandler(BaseUserHandler):
    """GET /users — list or search users with pagination and filters."""

    async def get(self):
        # 1. Pagination
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

        # 2. Filters
        active = self.get_argument("active", "true").lower()
        qtext = self.get_argument("q", "").strip()
        mode = self.get_argument("mode", "prefix").lower()  # new param: prefix|fuzzy

        must = []
        if active in ("true", "false"):
            must.append({"term": {"is_active": active == "true"}})

        if qtext:
            if mode == "fuzzy":
                # Fuzzy search across fields
                must.append({
                    "multi_match": {
                        "query": qtext,
                        "fields": ["username^2", "display_name"],
                        "type": "best_fields",
                        "fuzziness": "AUTO"
                    }
                })
            else:
                # Default: prefix search (no fuzziness allowed)
                must.append({
                    "multi_match": {
                        "query": qtext,
                        "fields": ["username^2", "display_name"],
                        "type": "phrase_prefix"
                    }
                })

        # Default to match_all if no filters
        es_query = {"bool": {"must": must or [{"match_all": {}}]}}

        # 3. Execute ES query
        try:
            res = await es_io(
                es.search,
                index=ES_CONFIG["user_index"],
                query=es_query,
                sort=[{"_score" if qtext else "created_at": {"order": "desc"}}],
                from_=(page - 1) * size,
                size=size,
                _source=[
                    "username", "display_name", "bio",
                    "avatar_url", "created_at", "stats", "is_active"
                ],
            )

            # 4. Transform results
            items = []
            for hit in res["hits"]["hits"]:
                user_data = public_user_view(hit["_source"])
                user_data["is_active"] = hit["_source"].get("is_active", True)
                if qtext:
                    user_data["score"] = hit.get("_score")
                items.append(user_data)

            # 5. Pagination metadata
            total = res["hits"]["total"]["value"]
            total_pages = (total + size - 1) // size

            self.finish({
                "users": items,
                "pagination": {
                    "current_page": page,
                    "page_size": size,
                    "total_results": total,
                    "total_pages": total_pages,
                    "has_next": page < total_pages,
                    "has_prev": page > 1,
                },
                "query": qtext if qtext else None,
                "mode": mode
            })
        except Exception:
            logger.exception("LIST_OR_SEARCH_ERROR")
            self.set_status(500)
            self.finish({
                "error": {
                    "code": "FETCH_ERROR",
                    "message": ERROR_MESSAGES.get("fetch_error", "Could not retrieve users")
                }
            })
