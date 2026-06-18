import uuid
import json
from datetime import datetime, timezone
from typing import Any, List, cast

from fastapi import APIRouter, Depends, HTTPException

from app.core.database import get_db_conn
from app.dependencies.auth import (
    get_accessible_case_ids,
    require_case_access,
    require_role,
)
from app.schemas.auth import UserContext
from app.schemas.case import Case, CaseCreate

router = APIRouter()


@router.post("/", response_model=Case)
async def create_case(
    case_in: CaseCreate,
    current_user: UserContext = Depends(require_role("admin", "investigator")),
):
    conn = None
    try:
        conn = get_db_conn()
        case_id = str(uuid.uuid4())
        # We need a case number, generating a simple one
        case_number = f"NP-{datetime.now().strftime('%Y%m%d')}-{case_id[:4].upper()}"

        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO cases (id, case_number, title, description, status, created_by, created_at, updated_at)
                VALUES (%s, %s, %s, %s, 'open', %s, %s, %s)
                RETURNING *
                """,
                (
                    case_id,
                    case_number,
                    case_in.title,
                    case_in.description,
                    current_user.id,
                    datetime.now(timezone.utc),
                    datetime.now(timezone.utc),
                ),
            )
            new_case = dict(cast(Any, cur.fetchone()))
            cur.execute(
                """
                INSERT INTO case_members (case_id, user_id, role_name)
                VALUES (%s, %s, %s)
                ON CONFLICT (case_id, user_id) DO UPDATE SET role_name = EXCLUDED.role_name
                """,
                (case_id, current_user.id, "owner"),
            )
            
            from app.core.audit import log_audit_event
            log_audit_event(
                conn,
                current_user,
                action="create",
                target_type="case",
                target_id=case_id,
                case_id=case_id,
                metadata={"title": case_in.title}
            )

            conn.commit()
            return new_case
    except Exception as e:
        if conn is not None:
            conn.rollback()
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        if conn is not None:
            conn.close()


@router.get("/", response_model=List[Case])
async def list_cases(
    limit: int = 50,
    offset: int = 0,
    current_user: UserContext = Depends(
        require_role("admin", "investigator", "auditor")
    ),
):
    conn = None
    try:
        conn = get_db_conn()
        with conn.cursor() as cur:
            if current_user.role in ("admin", "auditor"):
                cur.execute(
                    "SELECT * FROM cases ORDER BY created_at DESC LIMIT %s OFFSET %s",
                    (limit, offset)
                )
            else:
                cur.execute(
                    """
                    SELECT DISTINCT c.*
                    FROM cases c
                    LEFT JOIN case_members cm ON cm.case_id = c.id
                    WHERE c.created_by = %s OR cm.user_id = %s
                    ORDER BY c.created_at DESC
                    LIMIT %s OFFSET %s
                    """,
                    (current_user.id, current_user.id, limit, offset),
                )
            return [dict(case_row) for case_row in cur.fetchall()]
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        if conn is not None:
            conn.close()


@router.patch("/{case_id}/close", response_model=Case)
async def close_case(
    case_id: str,
    current_user: UserContext = Depends(require_role("admin", "investigator")),
):
    conn = None
    try:
        conn = get_db_conn()
        with conn.cursor() as cur:
            require_case_access(conn, current_user, case_id, write=True)

            cur.execute(
                """
                UPDATE cases 
                SET status = 'closed', updated_at = NOW() 
                WHERE id = %s AND status != 'closed'
                RETURNING *
                """,
                (case_id,),
            )
            updated_case = cast(Any, cur.fetchone())
            
            if not updated_case:
                # If not returned, it either doesn't exist or is already closed. Let's check which.
                cur.execute("SELECT status FROM cases WHERE id = %s", (case_id,))
                status_row = cur.fetchone()
                if not status_row:
                    raise HTTPException(status_code=404, detail="Case not found")
                if status_row["status"] == 'closed':
                    raise HTTPException(status_code=400, detail="Case is already closed")
                
            updated_case = dict(updated_case)

            from app.core.audit import log_audit_event
            log_audit_event(
                conn,
                current_user,
                action="close_case",
                target_type="case",
                target_id=case_id,
                case_id=case_id,
                metadata={"previous_status": "open"}
            )

            conn.commit()
            return updated_case
    except Exception as e:
        if isinstance(e, HTTPException):
            raise e
        if conn is not None:
            conn.rollback()
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        if conn is not None:
            conn.close()

@router.get("/{case_id}/details")
async def get_case_details(
    case_id: str,
    current_user: UserContext = Depends(
        require_role("admin", "investigator", "auditor")
    ),
):
    conn = None
    try:
        conn = get_db_conn()
        with conn.cursor() as cur:
            require_case_access(conn, current_user, case_id)

            # 1. Fetch Case
            cur.execute("SELECT * FROM cases WHERE id = %s", (case_id,))
            case = cast(Any, cur.fetchone())
            if case:
                case = dict(case)
            if not case:
                raise HTTPException(status_code=404, detail="Case not found")

            # 2. Fetch Evidence Files
            cur.execute(
                """
                SELECT id, original_filename, status, byte_size, uploaded_at, parsed_at, sha256
                FROM evidence_files
                WHERE case_id = %s
                ORDER BY uploaded_at DESC
                """,
                (case_id,),
            )
            evidence = [dict(cast(Any, row)) for row in cur.fetchall()]
            for e in evidence:
                e["uploaded_at"] = e["uploaded_at"].isoformat()
                if e["parsed_at"]:
                    e["parsed_at"] = e["parsed_at"].isoformat()

            # 3. Fetch Custody Logs
            cur.execute(
                """
                SELECT c.id, c.action, c.occurred_at, c.details, u.display_name as actor_name
                FROM custody_events c
                LEFT JOIN users u ON c.actor_id = u.id
                WHERE c.case_id = %s
                ORDER BY c.occurred_at DESC
                """,
                (case_id,),
            )
            custody_logs = [dict(cast(Any, row)) for row in cur.fetchall()]
            for log in custody_logs:
                log["occurred_at"] = log["occurred_at"].isoformat()

            # 4. Fetch Security Alerts / Risks
            cur.execute(
                """
                SELECT id, evidence_id, source, rule_or_model_id, severity, status, title, explanation, flow_reference, created_at
                FROM alerts
                WHERE case_id = %s
                ORDER BY created_at DESC
                LIMIT 100
                """,
                (case_id,),
            )
            alerts = [dict(cast(Any, row)) for row in cur.fetchall()]
            for a in alerts:
                a["created_at"] = a["created_at"].isoformat()
                if isinstance(a["flow_reference"], str):
                    try:
                        a["flow_reference"] = json.loads(a["flow_reference"])
                    except:
                        pass
                if isinstance(a["explanation"], str):
                    try:
                        a["explanation"] = json.loads(a["explanation"])
                    except:
                        pass

            from app.core.audit import log_audit_event
            log_audit_event(
                conn,
                current_user,
                action="view",
                target_type="case",
                target_id=case_id,
                case_id=case_id
            )

            return {
                "case": case,
                "evidence": evidence,
                "custody_logs": custody_logs,
                "alerts": alerts
            }
    except Exception as e:
        if isinstance(e, HTTPException):
            raise e
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        if conn is not None:
            conn.close()
