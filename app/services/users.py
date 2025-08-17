from typing import Dict, Any, Optional
from settings import USER_PROFILE_CONFIG, USER_STATS_DEFAULTS, ES_CONFIG
from services.es_io import es_io
from services.es import es

def valid_url(url: Optional[str]) -> bool:
    return not url or bool(USER_PROFILE_CONFIG["url_pattern"].match(url))

def public_user_view(src: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "username": src.get("username"),
        "display_name": src.get("display_name", src.get("username")),
        "bio": src.get("bio", ""),
        "avatar_url": src.get("avatar_url"),
        "created_at": src.get("created_at"),
        "stats": src.get("stats", USER_STATS_DEFAULTS.copy()),
    }

async def is_admin(handler) -> bool:
    try:
        doc = (await es_io(es.get, index=ES_CONFIG["user_index"], id=handler.current_user["username"]))["_source"]
        return doc.get("role", ES_CONFIG["default_role"]) == "admin"
    except Exception:
        return False
