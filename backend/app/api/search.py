from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query

from app.core.database import get_db_conn
from app.dependencies.auth import (
    get_accessible_case_ids,
    require_case_access,
    require_role,
)
from app.schemas.auth import UserContext
from app.schemas.search import PacketMetadata
from app.services.elasticsearch import ElasticsearchService

router = APIRouter()


@router.get("/", response_model=List[PacketMetadata])
async def search(
    case_id: Optional[str] = Query(None, description="Filter by case ID"),
    source_ip: Optional[str] = Query(None, description="Filter by source IP address"),
    destination_ip: Optional[str] = Query(
        None, description="Filter by destination IP address"
    ),
    source_port: Optional[int] = Query(None, description="Filter by source port"),
    destination_port: Optional[int] = Query(
        None, description="Filter by destination port"
    ),
    protocol: Optional[str] = Query(
        None, description="Filter by protocol (e.g., TCP, UDP)"
    ),
    user_agent: Optional[str] = Query(None, description="Filter by HTTP User-Agent"),
    http_host: Optional[str] = Query(None, description="Filter by HTTP host"),
    tls_sni: Optional[str] = Query(None, description="Filter by TLS SNI"),
    dns_query: Optional[str] = Query(None, description="Filter by DNS query domain"),
    is_anomaly: Optional[bool] = Query(None, description="Filter by anomaly flag"),
    time_range: Optional[str] = Query(
        None, description="Filter by time range (format: start_iso,end_iso)"
    ),
    start_time: Optional[str] = Query(
        None, description="Filter by start time (ISO format)"
    ),
    end_time: Optional[str] = Query(
        None, description="Filter by end time (ISO format)"
    ),
    size: int = Query(100, ge=1, le=10000, description="Number of results to return"),
    from_: int = Query(0, alias="from", ge=0, description="Offset for pagination"),
    current_user: UserContext = Depends(
        require_role("admin", "investigator", "auditor")
    ),
    es_service: ElasticsearchService = Depends(ElasticsearchService),
):
    """
    Search packet metadata in Elasticsearch.
    """
    if time_range and (start_time or end_time):
        raise HTTPException(
            status_code=400,
            detail="Cannot provide both 'time_range' and 'start_time'/'end_time' parameters.",
        )

    if time_range:
        parts = [p.strip() for p in time_range.split(",")]
        if len(parts) > 2 or not any(parts):
            raise HTTPException(
                status_code=400,
                detail="Invalid 'time_range' format. Expected up to 2 comma-separated ISO timestamps, and at least one must be non-empty.",
            )
        start_time = parts[0] if parts[0] else None
        if len(parts) == 2:
            end_time = parts[1] if parts[1] else None

    conn = None
    try:
        conn = get_db_conn()
        accessible_case_ids = get_accessible_case_ids(conn, current_user)
        if case_id:
            require_case_access(conn, current_user, case_id)
        results = await es_service.search_packets(
            case_id=case_id,
            case_ids=None if case_id else accessible_case_ids,
            source_ip=source_ip,
            destination_ip=destination_ip,
            source_port=source_port,
            destination_port=destination_port,
            protocol=protocol,
            start_time=start_time,
            end_time=end_time,
            http_user_agent=user_agent,
            http_host=http_host,
            tls_sni=tls_sni,
            dns_query=dns_query,
            is_anomaly=is_anomaly,
            size=size,
            from_=from_,
        )
        return results
    finally:
        if conn is not None:
            conn.close()
