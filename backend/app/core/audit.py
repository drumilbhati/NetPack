import json
import logging
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from app.schemas.auth import UserContext

logger = logging.getLogger(__name__)

def log_audit_event(
    conn,
    user: UserContext,
    action: str,
    target_type: str,
    target_id: Optional[str] = None,
    case_id: Optional[str] = None,
    evidence_id: Optional[str] = None,
    metadata: Optional[Dict[str, Any]] = None,
    request_ip: Optional[str] = None,
    request_id: Optional[str] = None,
):
    """
    Logs an audit event to the database.
    """
    try:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO audit_events (
                    actor_id, actor_role, action, target_type, target_id,
                    case_id, evidence_id, request_id, request_ip,
                    occurred_at, metadata
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                """,
                (
                    user.id,
                    user.role,
                    action,
                    target_type,
                    target_id,
                    case_id,
                    evidence_id,
                    request_id,
                    request_ip,
                    datetime.now(timezone.utc),
                    json.dumps(metadata or {}),
                ),
            )
            conn.commit()
    except Exception as e:
        # We don't want audit logging failure to crash the main request,
        # but we should log the failure.
        logger.error(f"Failed to log audit event: {e}")
        conn.rollback()
