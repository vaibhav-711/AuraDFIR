from elasticsearch import Elasticsearch

from app import config

_client = None


def get_es() -> Elasticsearch:
    global _client
    if _client is None:
        kwargs = {"request_timeout": 60}
        if config.ES_USER:
            kwargs["basic_auth"] = (config.ES_USER, config.ES_PASSWORD)
        _client = Elasticsearch(config.ES_URL, **kwargs)
    return _client
