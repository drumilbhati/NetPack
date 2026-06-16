import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException

from app.core.database import get_db_conn
from app.schemas.case import Case, CaseCreate

router = APIRouter()


@router.post("/", response_model=Case)
async def create_case(case_in: CaseCreate):
    try:
        conn = get_db_conn()
        case_id = str(uuid.uuid4())
        # We need a case number, generating a simple one
        case_number = f"NP-{datetime.now().strftime('%Y%m%d')}-{case_id[:4].upper()}"

        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO cases (id, case_number, title, description, status, created_at, updated_at)
                VALUES (%s, %s, %s, %s, 'open', %s, %s)
                RETURNING *
                """,
                (
                    case_id,
                    case_number,
                    case_in.title,
                    case_in.description,
                    datetime.now(timezone.utc),
                    datetime.now(timezone.utc),
                ),
            )
            new_case = cur.fetchone()
            conn.commit()
            return new_case
    except Exception as e:
        if "conn" in locals():
            conn.rollback()
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        if "conn" in locals():
            conn.close()


@router.get("/", response_model=List[Case])
async def list_cases():
    try:
        conn = get_db_conn()
        with conn.cursor() as cur:
            cur.execute("SELECT * FROM cases ORDER BY created_at DESC")
            return cur.fetchall()
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        if "conn" in locals():
            conn.close()


@router.get("/{case_id}/details")
async def get_case_details(case_id: str):
    try:
        conn = get_db_conn()
        with conn.cursor() as cur:
            # 1. Fetch Case
            cur.execute("SELECT * FROM cases WHERE id = %s", (case_id,))
            case = cur.fetchone()
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
            evidence = cur.fetchall()
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
            custody_logs = cur.fetchall()
            for log in custody_logs:
                log["occurred_at"] = log["occurred_at"].isoformat()

            return {"case": case, "evidence": evidence, "custody_logs": custody_logs}
    except Exception as e:
        if isinstance(e, HTTPException):
            raise e
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        if "conn" in locals():
            conn.close()
