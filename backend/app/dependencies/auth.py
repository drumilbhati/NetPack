from __future__ import annotations

from typing import Any, List, Optional, cast

from app.core.database import get_db_conn
from app.core.security import decode_access_token
from app.schemas.auth import UserContext
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

bearer_scheme = HTTPBearer(auto_error=False)


async def get_current_user(
    credentials: HTTPAuthorizationCredentials | None = Depends(bearer_scheme),
) -> UserContext:
    if credentials is None or credentials.scheme.lower() != "bearer":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required",
            headers={"WWW-Authenticate": "Bearer"},
        )

    payload = decode_access_token(credentials.credentials)
    user_id = payload.get("sub")
    if not user_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication token",
            headers={"WWW-Authenticate": "Bearer"},
        )

    conn = None
    try:
        conn = get_db_conn()
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT u.id, u.email, u.display_name, u.is_active, r.name AS role
                FROM users u
                JOIN roles r ON u.role_id = r.id
                WHERE u.id = %s
                """,
                (user_id,),
            )
            row = cast(Any, cur.fetchone())
            if row:
                row = dict(row)
            if not row:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="User not found",
                    headers={"WWW-Authenticate": "Bearer"},
                )
            if not row["is_active"]:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="User account is inactive",
                )
            return UserContext(
                id=str(row["id"]),
                email=row["email"],
                display_name=row["display_name"],
                role=row["role"],
                is_active=row["is_active"],
            )
    finally:
        if conn is not None:
            conn.close()


def require_role(*allowed_roles: str):
    async def _require_role(
        current_user: UserContext = Depends(get_current_user),
    ) -> UserContext:
        if current_user.role not in set(allowed_roles):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Insufficient role permissions",
            )
        return current_user

    return _require_role


def get_accessible_case_ids(conn, user: UserContext) -> Optional[List[str]]:
    if user.role in ("admin", "auditor"):
        return None

    with conn.cursor() as cur:
        cur.execute(
            """
            SELECT DISTINCT c.id
            FROM cases c
            LEFT JOIN case_members cm ON cm.case_id = c.id
            WHERE c.created_by = %s OR cm.user_id = %s
            ORDER BY c.id
            """,
            (user.id, user.id),
        )
        rows = cur.fetchall()
    return [str(row["id"]) for row in rows]


def require_case_access(
    conn, user: UserContext, case_id: str, write: bool = False
) -> None:
    if write and user.role not in {"admin", "investigator"}:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You do not have permission to modify this case",
        )

    if user.role in ("admin", "auditor"):
        return

    with conn.cursor() as cur:
        cur.execute(
            """
            SELECT 1
            FROM cases c
            LEFT JOIN case_members cm ON cm.case_id = c.id
            WHERE c.id = %s AND (c.created_by = %s OR cm.user_id = %s)
            LIMIT 1
            """,
            (case_id, user.id, user.id),
        )
        if cur.fetchone() is None:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="You do not have access to this case",
            )


async def get_filtered_case_ids(
    conn, user: UserContext, es_service: Any
) -> Optional[List[str]]:
    accessible_ids = get_accessible_case_ids(conn, user)
    if accessible_ids is None:
        return None

    active_ids = await es_service.get_active_case_ids()
    accessible_set = set(accessible_ids)
    return [cid for cid in active_ids if cid in accessible_set]

