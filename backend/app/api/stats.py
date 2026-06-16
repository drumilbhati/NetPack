from typing import Any, Dict, List

from fastapi import APIRouter

from app.services.elasticsearch import ElasticsearchService

router = APIRouter()
es_service = ElasticsearchService()


@router.get("/throughput")
async def get_throughput():
    buckets = await es_service.get_throughput_stats()
    return [
        {
            "timestamp": b["key_as_string"],
            "bytes_sent": b["bytes_sent"]["value"],
            "bytes_received": b["bytes_received"]["value"],
        }
        for b in buckets
    ]


@router.get("/protocols")
async def get_protocols():
    buckets = await es_service.get_protocol_stats()
    return [{"protocol": b["key"], "count": b["doc_count"]} for b in buckets]


@router.get("/top-talkers")
async def get_top_talkers():
    buckets = await es_service.get_top_talkers()
    return [{"ip": b["key"], "bytes": b["total_bytes"]["value"]} for b in buckets]
