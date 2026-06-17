from typing import Any, Dict, List, Optional, cast

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel

from app.core.database import get_db_conn
from app.dependencies.auth import (
    get_accessible_case_ids,
    require_case_access,
    require_role,
)
from app.schemas.auth import UserContext

router = APIRouter()


class AlertUpdate(BaseModel):
    status: str  # 'open', 'investigating', 'confirmed', 'false_positive', 'closed'


@router.get("/")
async def list_alerts(
    case_id: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
    severity: Optional[str] = Query(None),
    limit: int = 100,
    current_user: UserContext = Depends(
        require_role("admin", "investigator", "auditor")
    ),
):
    conn = None
    try:
        conn = get_db_conn()
        with conn.cursor() as cur:
            accessible_case_ids = get_accessible_case_ids(conn, current_user)
            query = "SELECT * FROM alerts WHERE 1=1"
            params = []

            if case_id:
                require_case_access(conn, current_user, case_id)
                query += " AND case_id = %s"
                params.append(case_id)
            elif accessible_case_ids is not None:
                if not accessible_case_ids:
                    return []
                placeholders = ",".join(["%s"] * len(accessible_case_ids))
                query += f" AND case_id IN ({placeholders})"
                params.extend(accessible_case_ids)
            if status:
                query += " AND status = %s"
                params.append(status)
            if severity:
                query += " AND severity = %s"
                params.append(severity)

            query += " ORDER BY created_at DESC LIMIT %s"
            params.append(limit)

            cur.execute(query, tuple(params))
            alerts = [dict(cast(Any, row)) for row in cur.fetchall()]

            # Convert datetime to string for JSON serialization
            for a in alerts:
                a["created_at"] = a["created_at"].isoformat()
                a["updated_at"] = a["updated_at"].isoformat()

            return alerts
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        if conn is not None:
            conn.close()


@router.patch("/{alert_id}/status")
async def update_alert_status(
    alert_id: str,
    update: AlertUpdate,
    current_user: UserContext = Depends(require_role("admin", "investigator")),
):
    valid_statuses = ["open", "investigating", "confirmed", "false_positive", "closed"]
    if update.status not in valid_statuses:
        raise HTTPException(
            status_code=400, detail=f"Invalid status. Must be one of {valid_statuses}"
        )

    conn = None
    try:
        conn = get_db_conn()
        with conn.cursor() as cur:
            cur.execute("SELECT case_id FROM alerts WHERE id = %s", (alert_id,))
            alert_row = cast(Any, cur.fetchone())
            if alert_row:
                alert_row = dict(alert_row)
            if not alert_row:
                raise HTTPException(status_code=404, detail="Alert not found")
            require_case_access(
                conn, current_user, str(alert_row["case_id"]), write=True
            )
            cur.execute(
                "UPDATE alerts SET status = %s, updated_at = NOW() WHERE id = %s RETURNING *",
                (update.status, alert_id),
            )
            updated_alert = cast(Any, cur.fetchone())
            if updated_alert:
                updated_alert = dict(updated_alert)

            conn.commit()
            updated_alert["created_at"] = updated_alert["created_at"].isoformat()
            updated_alert["updated_at"] = updated_alert["updated_at"].isoformat()
            return updated_alert
    except Exception as e:
        if isinstance(e, HTTPException):
            raise e
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        if conn is not None:
            conn.close()
