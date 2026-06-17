from typing import Any, Dict, List

from fastapi import APIRouter, Depends

from app.core.database import get_db_conn
from app.dependencies.auth import get_accessible_case_ids, require_role
from app.schemas.auth import UserContext
from app.services.elasticsearch import ElasticsearchService

router = APIRouter()
es_service = ElasticsearchService()


@router.get("/throughput")
async def get_throughput(
    current_user: UserContext = Depends(
        require_role("admin", "investigator", "auditor")
    ),
):
    conn = get_db_conn()
    try:
        accessible_case_ids = get_accessible_case_ids(conn, current_user)
        buckets = await es_service.get_throughput_stats(case_ids=accessible_case_ids)
        return [
            {
                "timestamp": b["key_as_string"],
                "bytes_sent": b["bytes_sent"]["value"],
                "bytes_received": b["bytes_received"]["value"],
            }
            for b in buckets
        ]
    finally:
        conn.close()


@router.get("/protocols")
async def get_protocols(
    current_user: UserContext = Depends(
        require_role("admin", "investigator", "auditor")
    ),
):
    conn = get_db_conn()
    try:
        accessible_case_ids = get_accessible_case_ids(conn, current_user)
        buckets = await es_service.get_protocol_stats(case_ids=accessible_case_ids)
        return [{"protocol": b["key"], "count": b["doc_count"]} for b in buckets]
    finally:
        conn.close()


@router.get("/top-talkers")
async def get_top_talkers(
    current_user: UserContext = Depends(
        require_role("admin", "investigator", "auditor")
    ),
):
    conn = get_db_conn()
    try:
        accessible_case_ids = get_accessible_case_ids(conn, current_user)
        buckets = await es_service.get_top_talkers(case_ids=accessible_case_ids)
        return [{"ip": b["key"], "bytes": b["total_bytes"]["value"]} for b in buckets]
    finally:
        conn.close()
