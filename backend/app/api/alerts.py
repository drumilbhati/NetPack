import os
from typing import Any, Dict, List, Optional

import psycopg2
from fastapi import APIRouter, Body, HTTPException, Query
from psycopg2.extras import RealDictCursor
from pydantic import BaseModel

router = APIRouter()


class AlertUpdate(BaseModel):
    status: str  # 'open', 'investigating', 'confirmed', 'false_positive', 'closed'


def get_db_conn():
    db_url = os.getenv(
        "DATABASE_URL",
        "postgresql://netpack:netpack_dev_password@localhost:5432/netpack",
    )
    if "localhost" in db_url and os.getenv("DOCKER_ENV"):
        db_url = db_url.replace("localhost", "postgres")
    return psycopg2.connect(db_url, cursor_factory=RealDictCursor)


@router.get("/")
async def list_alerts(
    case_id: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
    severity: Optional[str] = Query(None),
    limit: int = 100,
):
    try:
        conn = get_db_conn()
        with conn.cursor() as cur:
            query = "SELECT * FROM alerts WHERE 1=1"
            params = []

            if case_id:
                query += " AND case_id = %s"
                params.append(case_id)
            if status:
                query += " AND status = %s"
                params.append(status)
            if severity:
                query += " AND severity = %s"
                params.append(severity)

            query += " ORDER BY created_at DESC LIMIT %s"
            params.append(limit)

            cur.execute(query, tuple(params))
            alerts = cur.fetchall()

            # Convert datetime to string for JSON serialization
            for a in alerts:
                a["created_at"] = a["created_at"].isoformat()
                a["updated_at"] = a["updated_at"].isoformat()

            return alerts
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        if "conn" in locals():
            conn.close()


@router.patch("/{alert_id}/status")
async def update_alert_status(alert_id: str, update: AlertUpdate):
    valid_statuses = ["open", "investigating", "confirmed", "false_positive", "closed"]
    if update.status not in valid_statuses:
        raise HTTPException(
            status_code=400, detail=f"Invalid status. Must be one of {valid_statuses}"
        )

    try:
        conn = get_db_conn()
        with conn.cursor() as cur:
            cur.execute(
                "UPDATE alerts SET status = %s, updated_at = NOW() WHERE id = %s RETURNING *",
                (update.status, alert_id),
            )
            updated_alert = cur.fetchone()
            if not updated_alert:
                raise HTTPException(status_code=404, detail="Alert not found")

            conn.commit()
            updated_alert["created_at"] = updated_alert["created_at"].isoformat()
            updated_alert["updated_at"] = updated_alert["updated_at"].isoformat()
            return updated_alert
    except Exception as e:
        if isinstance(e, HTTPException):
            raise e
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        if "conn" in locals():
            conn.close()
