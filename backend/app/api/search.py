from typing import List, Optional

from fastapi import APIRouter, Depends, Query, HTTPException

from app.schemas.search import PacketMetadata
from app.services.elasticsearch import ElasticsearchService

router = APIRouter()


@router.get("/", response_model=List[PacketMetadata])
async def search(
    source_ip: Optional[str] = Query(None, description="Filter by source IP address"),
    destination_ip: Optional[str] = Query(None, description="Filter by destination IP address"),
    protocol: Optional[str] = Query(None, description="Filter by protocol (e.g., TCP, UDP)"),
    time_range: Optional[str] = Query(
        None, description="Filter by time range (format: start_iso,end_iso)"
    ),
    start_time: Optional[str] = Query(
        None, description="Filter by start time (ISO format)"
    ),
    end_time: Optional[str] = Query(None, description="Filter by end time (ISO format)"),
    size: int = Query(100, ge=1, le=10000, description="Number of results to return"),
    from_: int = Query(0, alias="from", ge=0, description="Offset for pagination"),
    es_service: ElasticsearchService = Depends(ElasticsearchService),
):
    """
    Search packet metadata in Elasticsearch.
    """
    if time_range and (start_time or end_time):
        raise HTTPException(
            status_code=400,
            detail="Cannot provide both 'time_range' and 'start_time'/'end_time' parameters."
        )

    if time_range:
        parts = [p.strip() for p in time_range.split(",")]
        if len(parts) > 2 or not any(parts):
            raise HTTPException(
                status_code=400,
                detail="Invalid 'time_range' format. Expected up to 2 comma-separated ISO timestamps, and at least one must be non-empty."
            )
        start_time = parts[0] if parts[0] else None
        if len(parts) == 2:
            end_time = parts[1] if parts[1] else None

    results = await es_service.search_packets(
        source_ip=source_ip,
        destination_ip=destination_ip,
        protocol=protocol,
        start_time=start_time,
        end_time=end_time,
        size=size,
        from_=from_,
    )
    return results
