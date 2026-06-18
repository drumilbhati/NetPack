import os
from typing import Any, Dict, List, Optional

import httpx
from fastapi import HTTPException

ELASTICSEARCH_URL = os.getenv("ELASTICSEARCH_URL", "http://localhost:9200")
INDEX_NAME = "netpack-flows"


class ElasticsearchService:
    @staticmethod
    async def _request_json(method: str, path: str, body: Any = None) -> Any:
        if not ELASTICSEARCH_URL:
            raise HTTPException(
                status_code=500, detail="ELASTICSEARCH_URL is not configured"
            )
        url = f"{ELASTICSEARCH_URL.rstrip('/')}/{path}"
        headers = {"Accept": "application/json"}
        if body is not None:
            headers["Content-Type"] = "application/json"

        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                response = await client.request(method, url, json=body, headers=headers)
                response.raise_for_status()
                return response.json() if response.content else {}
        except httpx.HTTPStatusError as exc:
            detail = exc.response.text
            raise HTTPException(
                status_code=exc.response.status_code,
                detail=f"Elasticsearch error: {detail}",
            ) from exc
        except httpx.RequestError as exc:
            raise HTTPException(
                status_code=503,
                detail=f"Elasticsearch unavailable: {str(exc)}",
            ) from exc

    async def search_packets(
        self,
        case_id: Optional[str] = None,
        case_ids: Optional[List[str]] = None,
        source_ip: Optional[str] = None,
        destination_ip: Optional[str] = None,
        source_port: Optional[int] = None,
        destination_port: Optional[int] = None,
        protocol: Optional[str] = None,
        start_time: Optional[str] = None,
        end_time: Optional[str] = None,
        http_user_agent: Optional[str] = None,
        http_host: Optional[str] = None,
        tls_sni: Optional[str] = None,
        dns_query: Optional[str] = None,
        is_anomaly: Optional[bool] = None,
        size: int = 100,
        from_: int = 0,
    ) -> List[Dict[str, Any]]:
        filter_clauses: List[Dict[str, Any]] = []

        if case_ids is not None and not case_ids:
            return []

        def add_term(field: str, value: Any) -> None:
            if value is not None and value != "":
                filter_clauses.append({"term": {field: value}})

        def add_wildcard(field: str, value: Optional[str]) -> None:
            if not value:
                return
            pattern = value.strip()
            if not pattern:
                return
            if "*" not in pattern and "?" not in pattern:
                pattern = f"*{pattern}*"
            filter_clauses.append(
                {
                    "wildcard": {
                        field: {
                            "value": pattern,
                            "case_insensitive": True,
                        }
                    }
                }
            )

        add_term("case_id", case_id)
        if case_ids is not None and case_ids:
            filter_clauses.append({"terms": {"case_id": case_ids}})
        add_term("source_ip", source_ip)
        add_term("destination_ip", destination_ip)
        add_term("source_port", source_port)
        add_term("destination_port", destination_port)
        add_term("protocol", protocol)
        add_wildcard("http_user_agent", http_user_agent)
        add_wildcard("http_host", http_host)
        add_wildcard("tls_sni", tls_sni)
        add_wildcard("dns_query", dns_query)
        if is_anomaly is not None:
            add_term("is_anomaly", is_anomaly)

        if start_time or end_time:
            time_range: Dict[str, Any] = {}
            if start_time:
                time_range["gte"] = start_time
            if end_time:
                time_range["lte"] = end_time
            filter_clauses.append({"range": {"timestamp": time_range}})

        final_query = (
            {"match_all": {}}
            if not filter_clauses
            else {"bool": {"filter": filter_clauses}}
        )

        body = {
            "query": final_query,
            "size": size,
            "from": from_,
            "sort": [{"timestamp": {"order": "desc"}}],
        }

        response = await self._request_json("POST", f"{INDEX_NAME}/_search", body)
        hits = response.get("hits", {}).get("hits", [])
        return [hit["_source"] for hit in hits]

    async def get_recent_sessions(
        self,
        case_id: Optional[str] = None,
        case_ids: Optional[List[str]] = None,
        size: int = 50,
    ) -> List[Dict[str, Any]]:
        if case_ids is not None and not case_ids:
            return []
        query = {"match_all": {}}
        if case_id:
            query = {"term": {"case_id": case_id}}
        elif case_ids is not None:
            query = {"terms": {"case_id": case_ids}}

        body = {
            "query": query,
            "sort": [{"timestamp": {"order": "desc"}}],
            "size": size,
        }

        try:
            response = await self._request_json("POST", f"{INDEX_NAME}/_search", body)
            hits = response.get("hits", {}).get("hits", [])
            return [hit["_source"] for hit in hits]
        except Exception:
            return []

    async def get_throughput_stats(
        self, interval: str = "1d", case_ids: Optional[List[str]] = None
    ) -> List[Dict[str, Any]]:
        if case_ids is not None and not case_ids:
            return []
        
        # Determine dynamic interval based on the data we are querying.
        # We default to 1d (daily) to handle 90-day datasets smoothly.
        # If we need higher resolution later, we can pass it from the frontend.
        body = {
            "size": 0,
            "query": {"terms": {"case_id": case_ids}}
            if case_ids is not None
            else {"match_all": {}},
            "aggs": {
                "throughput": {
                    "date_histogram": {
                        "field": "timestamp",
                        "calendar_interval": interval,
                    },
                    "aggs": {
                        "bytes_sent": {"sum": {"field": "bytes_sent"}},
                        "bytes_received": {"sum": {"field": "bytes_received"}},
                    },
                }
            },
        }
        try:
            response = await self._request_json("POST", f"{INDEX_NAME}/_search", body)
            buckets = (
                response.get("aggregations", {})
                .get("throughput", {})
                .get("buckets", [])
            )
            return buckets
        except Exception:
            return []


    async def get_protocol_stats(
        self, case_ids: Optional[List[str]] = None
    ) -> List[Dict[str, Any]]:
        if case_ids is not None and not case_ids:
            return []
        body = {
            "size": 0,
            "query": {"terms": {"case_id": case_ids}}
            if case_ids is not None
            else {"match_all": {}},
            "aggs": {"protocols": {"terms": {"field": "protocol"}}},
        }
        try:
            response = await self._request_json("POST", f"{INDEX_NAME}/_search", body)
            buckets = (
                response.get("aggregations", {}).get("protocols", {}).get("buckets", [])
            )
            return buckets
        except Exception:
            return []

    async def get_top_talkers(
        self, size: int = 10, case_ids: Optional[List[str]] = None
    ) -> List[Dict[str, Any]]:
        if case_ids is not None and not case_ids:
            return []
        body = {
            "size": 0,
            "query": {"terms": {"case_id": case_ids}}
            if case_ids is not None
            else {"match_all": {}},
            "aggs": {
                "top_talkers": {
                    "terms": {
                        "field": "source_ip",
                        "size": size,
                        "order": {"total_bytes": "desc"},
                    },
                    "aggs": {"total_bytes": {"sum": {"field": "bytes_sent"}}},
                }
            },
        }
        try:
            response = await self._request_json("POST", f"{INDEX_NAME}/_search", body)
            buckets = (
                response.get("aggregations", {})
                .get("top_talkers", {})
                .get("buckets", [])
            )
            return buckets
        except Exception:
            return []

    async def get_active_case_ids(self) -> List[str]:
        body = {
            "size": 0,
            "aggs": {
                "unique_cases": {
                    "terms": {
                        "field": "case_id",
                        "size": 1000
                    }
                }
            }
        }
        try:
            response = await self._request_json("POST", f"{INDEX_NAME}/_search", body)
            buckets = response.get("aggregations", {}).get("unique_cases", {}).get("buckets", [])
            return [b["key"] for b in buckets]
        except Exception:
            return []

