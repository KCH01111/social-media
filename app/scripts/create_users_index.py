# app/services/create_users_index.py
import logging
from elasticsearch import Elasticsearch
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
        "dynamic": True,
        "properties": {
            "username": {"type": "keyword"},
            "password_hash": {"type": "keyword"},
            "display_name": {
                "type": "text",
                "fields": {"keyword": {"type": "keyword"}}
            },
            "bio": {"type": "text"},
            "avatar_url": {"type": "keyword"},
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
    if es.indices.exists(index=ES_CONFIG["user_index"]):
        logger.info("%s index already exists", ES_CONFIG["user_index"])
        return
    res = es.indices.create(index=ES_CONFIG["user_index"], body=USERS_INDEX_SETTINGS)
    logger.info("Created index %s: %s", ES_CONFIG["user_index"], res)

if __name__ == "__main__":
    try:
        create_users_index()
    except Exception as e:
        logger.error("Error creating index: %r", e)
