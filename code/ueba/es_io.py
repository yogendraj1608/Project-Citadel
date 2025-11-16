from elasticsearch import Elasticsearch

def get_client(url, username, password):
    return Elasticsearch(
        url,
        basic_auth=(username, password),
        verify_certs=False,
        request_timeout=60,
    )

def fetch_auth_logs(es, index, history_days=30, page_size=10000, max_docs=150_000):
 
    body = {
        "size": page_size,
        "track_total_hits": False,
        "sort": [
            {"@timestamp": {"order": "desc", "unmapped_type": "date"}},
            {"_shard_doc": "desc"}  
        ],
        "query": {"range": {"@timestamp": {"gte": f"now-{history_days}d"}}},
        "_source": [
            "@timestamp","user.name","event.outcome","event.action",
            "system.auth.ssh.event","system.auth.ssh.method",
            "source.ip","source.geo.location","source.geo.country_iso_code",
            "source.as.number","host.name","message"
        ],
    }

    docs, search_after = [], None
    while True:
        if search_after:
            body["search_after"] = search_after
        res = es.search(index=index, body=body)
        hits = res["hits"]["hits"]
        if not hits:
            break

        for h in hits:
            s = h.get("_source", {})
            s["_index"] = h["_index"]
            s["_id"] = h["_id"]
            docs.append(s)

        search_after = hits[-1].get("sort")
        if not search_after or len(docs) >= max_docs:
            break

    return docs
