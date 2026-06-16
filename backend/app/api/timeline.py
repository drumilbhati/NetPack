import os
from typing import Any, Dict, List, Optional

import psycopg2
from fastapi import APIRouter, HTTPException, Query
from psycopg2.extras import RealDictCursor

from app.services.elasticsearch import ElasticsearchService

router = APIRouter()
es_service = ElasticsearchService()


def get_db_conn():
    db_url = os.getenv(
        "DATABASE_URL",
        "postgresql://netpack:netpack_dev_password@localhost:5432/netpack",
    )
    # If running inside docker, localhost might need to be postgres
    if "localhost" in db_url and os.getenv("DOCKER_ENV"):
        db_url = db_url.replace("localhost", "postgres")
    return psycopg2.connect(db_url, cursor_factory=RealDictCursor)


@router.get("/")
async def get_timeline(case_id: Optional[str] = Query(None)):
    timeline_events = []

    # 1. Fetch Evidence Files from Postgres
    try:
        conn = get_db_conn()
        with conn.cursor() as cur:
            # Evidence Imports
            query = "SELECT id, original_filename as title, uploaded_at as timestamp, 'evidence' as type FROM evidence_files"
            if case_id:
                cur.execute(
                    query + " WHERE case_id = %s ORDER BY uploaded_at DESC LIMIT 50",
                    (case_id,),
                )
            else:
                cur.execute(query + " ORDER BY uploaded_at DESC LIMIT 50")
            evidence_events = cur.fetchall()
            for e in evidence_events:
                e["timestamp"] = e["timestamp"].isoformat()
                timeline_events.append(dict(e))

            # Alerts
            query = "SELECT id, title, created_at as timestamp, severity, source, 'alert' as type FROM alerts"
            if case_id:
                cur.execute(
                    query + " WHERE case_id = %s ORDER BY created_at DESC LIMIT 50",
                    (case_id,),
                )
            else:
                cur.execute(query + " ORDER BY created_at DESC LIMIT 50")
            alert_events = cur.fetchall()
            for a in alert_events:
                a["timestamp"] = a["timestamp"].isoformat()
                timeline_events.append(dict(a))
        conn.close()
    except Exception as e:
        print(f"Timeline DB error: {e}")

    # 2. Fetch Sessions from Elasticsearch
    try:
        sessions = await es_service.get_recent_sessions(case_id=case_id, size=50)
        for s in sessions:
            timeline_events.append(
                {
                    "id": s.get("flow_id", str(os.urandom(8).hex())),
                    "title": f"Session: {s.get('source_ip')} -> {s.get('destination_ip')}",
                    "timestamp": s.get("timestamp"),
                    "type": "session",
                    "protocol": s.get("protocol"),
                    "bytes_sent": s.get("bytes_sent"),
                }
            )
    except Exception as e:
        print(f"Timeline ES error: {e}")

    # Sort by timestamp descending
    timeline_events.sort(
        key=lambda x: x["timestamp"] if x["timestamp"] else "", reverse=True
    )

    return timeline_events
