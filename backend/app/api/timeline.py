import os
from typing import Any, Dict, List, Optional, cast

from fastapi import APIRouter, Depends, Query

from app.core.database import get_db_conn
from app.dependencies.auth import (
    get_accessible_case_ids,
    get_filtered_case_ids,
    require_case_access,
    require_role,
)
from app.schemas.auth import UserContext
from app.services.elasticsearch import ElasticsearchService

router = APIRouter()
es_service = ElasticsearchService()


def _format_timestamp(value):
    return value.isoformat() if hasattr(value, "isoformat") else value


@router.get("/")
async def get_timeline(
    case_id: Optional[str] = Query(None),
    current_user: UserContext = Depends(
        require_role("admin", "investigator", "auditor")
    ),
):
    timeline_events: List[Dict[str, Any]] = []
    conn = None
    filtered_case_ids = None
    try:
        conn = get_db_conn()
        
        # Prefetch filtered case IDs for ES while connection is open
        if not case_id:
            filtered_case_ids = await get_filtered_case_ids(conn, current_user, es_service)
            
        with conn.cursor() as cur:
            if case_id:
                require_case_access(conn, current_user, case_id)
                cur.execute(
                    """
                    SELECT id, original_filename AS title, uploaded_at AS timestamp,
                           'evidence' AS type
                    FROM evidence_files
                    WHERE case_id = %s
                    ORDER BY uploaded_at DESC
                    LIMIT 50
                    """,
                    (case_id,),
                )
            elif current_user.role in ("admin", "auditor"):
                cur.execute(
                    """
                    SELECT id, original_filename AS title, uploaded_at AS timestamp,
                           'evidence' AS type
                    FROM evidence_files
                    ORDER BY uploaded_at DESC
                    LIMIT 50
                    """
                )
            else:
                cur.execute(
                    """
                    SELECT id, original_filename AS title, uploaded_at AS timestamp,
                           'evidence' AS type
                    FROM evidence_files
                    WHERE case_id IN (
                        SELECT DISTINCT c.id
                        FROM cases c
                        LEFT JOIN case_members cm ON cm.case_id = c.id
                        WHERE c.created_by = %s OR cm.user_id = %s
                    )
                    ORDER BY uploaded_at DESC
                    LIMIT 50
                    """,
                    (current_user.id, current_user.id),
                )
            evidence_events = [dict(cast(Any, row)) for row in cur.fetchall()]

            for event in evidence_events:
                event["timestamp"] = _format_timestamp(event["timestamp"])
                timeline_events.append(dict(event))

            if case_id:
                cur.execute(
                    """
                    SELECT id, title, created_at AS timestamp, severity, source, explanation, flow_reference,
                           'alert' AS type
                    FROM alerts
                    WHERE case_id = %s
                    ORDER BY created_at DESC
                    LIMIT 50
                    """,
                    (case_id,),
                )
            elif current_user.role in ("admin", "auditor"):
                cur.execute(
                    """
                    SELECT id, title, created_at AS timestamp, severity, source, explanation, flow_reference,
                           'alert' AS type
                    FROM alerts
                    ORDER BY created_at DESC
                    LIMIT 50
                    """
                )
            else:
                cur.execute(
                    """
                    SELECT id, title, created_at AS timestamp, severity, source, explanation, flow_reference,
                           'alert' AS type
                    FROM alerts
                    WHERE case_id IN (
                        SELECT DISTINCT c.id
                        FROM cases c
                        LEFT JOIN case_members cm ON cm.case_id = c.id
                        WHERE c.created_by = %s OR cm.user_id = %s
                    )
                    ORDER BY created_at DESC
                    LIMIT 50
                    """,
                    (current_user.id, current_user.id),
                )
            alert_events = [dict(cast(Any, row)) for row in cur.fetchall()]

            for event in alert_events:
                event["timestamp"] = _format_timestamp(event["timestamp"])
                timeline_events.append(dict(event))
    finally:
        if conn is not None:
            conn.close()

    try:
        sessions = await es_service.get_recent_sessions(
            case_id=case_id,
            case_ids=filtered_case_ids,
            size=50,
        )
        for session in sessions:
            timeline_events.append(
                {
                    "id": session.get("flow_id", str(os.urandom(8).hex())),
                    "title": f"Session: {session.get('source_ip')} -> {session.get('destination_ip')}",
                    "timestamp": session.get("timestamp"),
                    "type": "session",
                    "protocol": session.get("protocol"),
                    "bytes_sent": session.get("bytes_sent"),
                    "bytes_received": session.get("bytes_received"),
                    "source_ip": session.get("source_ip"),
                    "destination_ip": session.get("destination_ip"),
                    "source_port": session.get("source_port"),
                    "destination_port": session.get("destination_port"),
                    "is_anomaly": session.get("is_anomaly"),
                    "raw": session,
                }
            )
    except Exception as exc:
        print(f"Timeline ES error: {exc}")

    timeline_events.sort(key=lambda event: event["timestamp"] or "", reverse=True)
    return timeline_events
