import json
import os
from typing import Any, Dict, List, Optional

import httpx
from fastapi import HTTPException

ELASTICSEARCH_URL = os.getenv("ELASTICSEARCH_URL", "http://localhost:9200")
INDEX_NAME = "netpack-flows"


class ElasticsearchService:
    @staticmethod
    async def _request_json(method: str, path: str, body: Any = None) -> Any:
        url = f"{ELASTICSEARCH_URL.rstrip('/')}/{path}"
        headers = {"Accept": "application/json"}
        if body is not None:
            headers["Content-Type"] = "application/json"

        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                response = await client.request(
                    method, url, json=body, headers=headers
                )
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
        source_ip: Optional[str] = None,
        destination_ip: Optional[str] = None,
        protocol: Optional[str] = None,
        start_time: Optional[str] = None,
        end_time: Optional[str] = None,
        size: int = 100,
        from_: int = 0,
    ) -> List[Dict[str, Any]]:
        query = {"bool": {"must": []}}

        if source_ip:
            query["bool"]["must"].append({"term": {"source_ip": source_ip}})
        if destination_ip:
            query["bool"]["must"].append({"term": {"destination_ip": destination_ip}})
        if protocol:
            query["bool"]["must"].append({"term": {"protocol": protocol}})

        if start_time or end_time:
            time_range = {}
            if start_time:
                time_range["gte"] = start_time
            if end_time:
                time_range["lte"] = end_time
            query["bool"]["must"].append({"range": {"timestamp": time_range}})

        if not query["bool"]["must"]:
            raise HTTPException(
                status_code=400,
                detail="At least one search filter (IP, protocol, or time range) must be provided."
            )

        body = {"query": query, "size": size, "from": from_}

        response = await self._request_json("POST", f"{INDEX_NAME}/_search", body)
        hits = response.get("hits", {}).get("hits", [])
        return [hit["_source"] for hit in hits]
