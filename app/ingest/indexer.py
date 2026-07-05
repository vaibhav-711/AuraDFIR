from elasticsearch import helpers

from app import config
from app.es import get_es

LOG_MAPPING = {
    "mappings": {
        "properties": {
            "@timestamp": {"type": "date"},
            "source": {"properties": {"ip": {"type": "ip"}}},
            "http": {"properties": {
                "request": {"properties": {
                    "method": {"type": "keyword"},
                    "referrer": {"type": "keyword", "ignore_above": 2048},
                }},
                "response": {"properties": {
                    "status_code": {"type": "integer"},
                    "body": {"properties": {"bytes": {"type": "long"}}},
                }},
            }},
            "url": {"properties": {
                "original": {
                    "type": "keyword", "ignore_above": 4096,
                    "fields": {"text": {"type": "text"}},
                },
                "domain": {"type": "keyword", "ignore_above": 255},
            }},
            "user_agent": {"properties": {"original": {
                "type": "keyword", "ignore_above": 1024,
                "fields": {"text": {"type": "text"}},
            }}},
            "event": {"properties": {"original": {"type": "text", "index": False}}},
        }
    }
}


def ensure_index(index: str):
    es = get_es()
    if not es.indices.exists(index=index):
        es.indices.create(index=index, **LOG_MAPPING)


def index_events(case_id: int, events, chunk_size: int = 2000) -> tuple[int, int]:
    """Bulk-index parsed events into the case log index. Returns (ok, failed)."""
    index = config.case_log_index(case_id)
    ensure_index(index)
    es = get_es()
    ok = failed = 0
    actions = ({"_index": index, "_source": doc} for doc in events)
    for success, _ in helpers.streaming_bulk(es, actions, chunk_size=chunk_size,
                                             raise_on_error=False):
        ok += 1 if success else 0
        failed += 0 if success else 1
    es.indices.refresh(index=index)
    return ok, failed
