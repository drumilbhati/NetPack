#!/usr/bin/env python3
"""Index extracted packet metadata JSON into Elasticsearch."""

from __future__ import annotations

import argparse
import json
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

DEFAULT_INDEX = "netpack-flows"


class ElasticsearchError(RuntimeError):
    """Custom error for Elasticsearch requests with HTTP status code."""

    def __init__(self, message: str, status: int | None = None):
        super().__init__(message)
        self.status = status


INDEX_MAPPING = {
    "mappings": {
        "properties": {
            "case_id": {"type": "keyword"},
            "evidence_id": {"type": "keyword"},
            "sha256": {"type": "keyword"},
            "source_ip": {"type": "ip"},
            "destination_ip": {"type": "ip"},
            "source_port": {"type": "integer"},
            "destination_port": {"type": "integer"},
            "protocol": {"type": "keyword"},
            "timestamp": {"type": "date", "ignore_malformed": True},
            "metadata": {"type": "object", "enabled": True},
        }
    }
}


def request_json(method: str, url: str, body: Any | None = None) -> Any:
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise ValueError(
            f"Invalid URL scheme: {parsed.scheme}. Only http and https are allowed."
        )

    data = None
    headers = {"Accept": "application/json"}
    if body is not None:
        data = json.dumps(body).encode("utf-8")
        headers["Content-Type"] = "application/json"

    request = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(request, timeout=20) as response:
            raw = response.read()
            return json.loads(raw.decode("utf-8")) if raw else {}
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")
        raise ElasticsearchError(
            f"{method} {url} failed: {exc.code} {detail}", status=exc.code
        ) from exc
    except urllib.error.URLError as exc:
        raise ElasticsearchError(f"{method} {url} failed: {exc.reason}") from exc


def read_metadata(path: Path) -> list[dict[str, Any]]:
    text = path.read_text(encoding="utf-8").strip()
    if not text:
        return []

    if path.suffix.lower() == ".ndjson":
        return [json.loads(line) for line in text.splitlines() if line.strip()]

    loaded = json.loads(text)
    return normalize_payload(loaded)


def normalize_payload(payload: Any) -> list[dict[str, Any]]:
    if isinstance(payload, list):
        return [normalize_record(record, {}) for record in payload]

    if not isinstance(payload, dict):
        raise ValueError("metadata JSON must be an object, array, or NDJSON file")

    context = {
        "case_id": payload.get("case_id"),
        "evidence_id": payload.get("evidence_id"),
        "sha256": payload.get("sha256") or payload.get("pcap_sha256"),
    }
    records = (
        payload.get("records")
        or payload.get("flows")
        or payload.get("packets")
        or payload.get("metadata")
    )

    if records is None:
        return [normalize_record(payload, {})]
    if not isinstance(records, list):
        raise ValueError("metadata records must be a list")

    return [normalize_record(record, context) for record in records]


def normalize_record(record: Any, context: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(record, dict):
        raise ValueError("each metadata record must be a JSON object")

    source_ip = first_present(record, "source_ip", "src_ip", "src", "ip_src")
    destination_ip = first_present(
        record, "destination_ip", "dest_ip", "dst_ip", "dst", "ip_dst"
    )

    normalized = {
        "case_id": record.get("case_id") or context.get("case_id"),
        "evidence_id": record.get("evidence_id") or context.get("evidence_id"),
        "sha256": record.get("sha256")
        or record.get("pcap_sha256")
        or context.get("sha256"),
        "source_ip": source_ip,
        "destination_ip": destination_ip,
        "source_port": coerce_int(
            first_present(record, "source_port", "src_port", "sport")
        ),
        "destination_port": coerce_int(
            first_present(record, "destination_port", "dest_port", "dst_port", "dport")
        ),
        "protocol": first_present(record, "protocol", "proto"),
        "timestamp": first_present(record, "timestamp", "time", "ts"),
        "metadata": record,
    }

    return {key: value for key, value in normalized.items() if value is not None}


def first_present(record: dict[str, Any], *keys: str) -> Any:
    for key in keys:
        value = record.get(key)
        if value not in (None, ""):
            return value
    return None


def coerce_int(value: Any) -> int | None:
    if value in (None, ""):
        return None
    return int(value)


def ensure_index(es_url: str, index: str) -> None:
    try:
        request_json("HEAD", f"{es_url}/{index}")
    except ElasticsearchError as exc:
        if exc.status == 404:
            request_json("PUT", f"{es_url}/{index}", INDEX_MAPPING)
        else:
            raise


def bulk_index(
    es_url: str, index: str, records: list[dict[str, Any]]
) -> dict[str, Any]:
    lines: list[str] = []
    for record in records:
        lines.append(json.dumps({"index": {"_index": index}}))
        lines.append(json.dumps(record, separators=(",", ":")))
    payload = ("\n".join(lines) + "\n").encode("utf-8")

    request = urllib.request.Request(
        f"{es_url}/_bulk?refresh=wait_for",
        data=payload,
        headers={"Content-Type": "application/x-ndjson", "Accept": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            result = json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")
        raise ElasticsearchError(
            f"POST {es_url}/_bulk failed: {exc.code} {detail}", status=exc.code
        ) from exc
    except urllib.error.URLError as exc:
        raise ElasticsearchError(f"POST {es_url}/_bulk failed: {exc.reason}") from exc

    if result.get("errors"):
        raise ElasticsearchError(
            f"bulk index reported errors: {json.dumps(result, indent=2)}"
        )
    return result


def query_ip(es_url: str, index: str, ip: str) -> dict[str, Any]:
    body = {
        "query": {
            "bool": {
                "should": [
                    {"match": {"source_ip": ip}},
                    {"match": {"destination_ip": ip}},
                ],
                "minimum_should_match": 1,
            }
        }
    }
    return request_json("POST", f"{es_url}/{index}/_search", body)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Index extracted packet metadata JSON into Elasticsearch."
    )
    parser.add_argument(
        "metadata_json",
        type=Path,
        help="JSON or NDJSON metadata file produced by ingestion.",
    )
    parser.add_argument(
        "--es-url", default="http://127.0.0.1:9200", help="Elasticsearch URL."
    )
    parser.add_argument(
        "--index", default=DEFAULT_INDEX, help="Elasticsearch index name."
    )
    parser.add_argument(
        "--query-ip", help="Query this IP after indexing and print matching hit count."
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Parse and normalize records without contacting Elasticsearch.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    records = read_metadata(args.metadata_json)
    if not records:
        print("No metadata records found.", file=sys.stderr)
        return 1

    if args.dry_run:
        print(
            json.dumps({"records": len(records), "first_record": records[0]}, indent=2)
        )
        return 0

    es_url = args.es_url.rstrip("/")
    ensure_index(es_url, args.index)
    result = bulk_index(es_url, args.index, records)
    print(
        f"Indexed {len(records)} records into {args.index}; took={result.get('took')}ms"
    )

    if args.query_ip:
        response = query_ip(es_url, args.index, args.query_ip)
        total = response.get("hits", {}).get("total", {})
        count = total.get("value", total) if isinstance(total, dict) else total
        print(f"Query IP {args.query_ip}: {count} hits")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
