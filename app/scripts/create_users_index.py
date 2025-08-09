# scripts/setup_indexes.py
from elasticsearch import Elasticsearch
es = Elasticsearch("http://localhost:9200")

def create_users_index():
    if es.indices.exists(index="users"):
        print("users index already exists"); return
    body = {
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
    res = es.indices.create(index="users", body=body)
    print("created users:", res)

def create_posts_index():
    if es.indices.exists(index="posts"):
        print("posts index already exists"); return
    body = {
        "settings": {
            "number_of_shards": 1,
            "number_of_replicas": 0,
            "refresh_interval": "1s"
        },
        "mappings": {
            "dynamic": True,
            "properties": {
                "id": {"type": "keyword"},
                "author_id": {"type": "keyword"},
                "text": {"type": "text"},
                "image_url": {"type": "keyword"},
                "tags": {"type": "keyword"},
                "likes_count": {"type": "integer"},
                "is_deleted": {"type": "boolean"},
                "created_at": {"type": "date"},
                "updated_at": {"type": "date"}
            }
        }
    }
    res = es.indices.create(index="posts", body=body)
    print("created posts:", res)

def setup_indexes():
    try:
        create_users_index()
        create_posts_index()
    except Exception as e:
        print("Error creating indexes:", repr(e))

if __name__ == "__main__":
    setup_indexes()
