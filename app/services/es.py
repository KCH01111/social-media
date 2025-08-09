import os
from elasticsearch import Elasticsearch

ES_HOST = os.getenv("ES_HOST", "http://localhost:9200")
ES_USER = os.getenv("ES_USER")
ES_PASS = os.getenv("ES_PASS")

# Create Elasticsearch client
if ES_USER and ES_PASS:
    es = Elasticsearch(
        ES_HOST,
        basic_auth=(ES_USER, ES_PASS),
        verify_certs=False  # change to True if using HTTPS with valid cert
    )
else:
    es = Elasticsearch(ES_HOST)

# Optional: ping to check connection
if not es.ping():
    raise RuntimeError(f"Cannot connect to Elasticsearch at {ES_HOST}")
