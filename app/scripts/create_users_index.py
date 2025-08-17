import logging
from elasticsearch import Elasticsearch, NotFoundError, BadRequestError
from app.settings import ES_CONFIG

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

es = Elasticsearch(ES_CONFIG["url"])

USERS_INDEX_SETTINGS = {
    "settings": {
        "number_of_shards": 1,
        "number_of_replicas": 0,
        "refresh_interval": "1s"
    },
    "mappings": {
        "dynamic": "strict",
        "properties": {
            "username": {"type": "keyword"},
            "password_hash": {"type": "keyword", "index": False},
            "display_name": {
                "type": "text",
                "fields": {"raw": {"type": "keyword", "ignore_above": 256}}
            },
            "bio": {"type": "text"},
            "avatar_url": {"type": "keyword", "index": False},
            "email": {"type": "keyword"},
            "role": {"type": "keyword"},
            "is_active": {"type": "boolean"},
            "created_at": {"type": "date"},
            "updated_at": {"type": "date"},
            "stats": {
                "type": "object",
                "properties": {
                    "posts_count": {"type": "integer"},
                    "followers_count": {"type": "integer"},
                    "following_count": {"type": "integer"}
                }
            }
        }
    }
}


def create_users_index():
    """Create the users index if it doesn't exist."""
    try:
        exists = False
        try:
            exists = es.indices.exists(index=ES_CONFIG["user_index"])
        except (NotFoundError, BadRequestError):
            exists = False

        if exists:
            logger.info("%s index already exists", ES_CONFIG["user_index"])
            return

        res = es.indices.create(
            index=ES_CONFIG["user_index"],
            body=USERS_INDEX_SETTINGS
        )
        logger.info("Created index %s: %s", ES_CONFIG["user_index"], res)

    except Exception as e:
        logger.error("Error creating index: %r", e)


if __name__ == "__main__":
    create_users_index()
