from __future__ import annotations

from typing import Any, cast

from fastapi import APIRouter, Depends, HTTPException, status

from app.core.database import get_db_conn
from app.core.security import create_access_token, verify_password
from app.dependencies.auth import get_current_user
from app.schemas.auth import LoginRequest, TokenResponse, UserContext

router = APIRouter()


@router.post("/login", response_model=TokenResponse)
async def login(payload: LoginRequest) -> TokenResponse:
    conn = None
    conn = get_db_conn()
    try:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT u.id, u.email, u.display_name, u.password_hash, u.is_active, r.name AS role
                FROM users u
                JOIN roles r ON u.role_id = r.id
                WHERE LOWER(u.email) = LOWER(%s)
                """,
                (payload.email,),
            )
            row = cast(Any, cur.fetchone())
            if row:
                row = dict(row)

        if not row:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid email or password",
            )

        password_hash = row.get("password_hash")
        if not password_hash:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Password hashing is not initialized for this user",
            )
        if not row["is_active"]:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="User account is inactive",
            )
        if not verify_password(payload.password, password_hash):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid email or password",
            )

        user = UserContext(
            id=str(row["id"]),
            email=row["email"],
            display_name=row["display_name"],
            role=row["role"],
            is_active=row["is_active"],
        )
        token = create_access_token(
            {
                "sub": user.id,
                "email": user.email,
                "display_name": user.display_name,
                "role": user.role,
            }
        )

        from app.core.audit import log_audit_event
        log_audit_event(
            conn,
            user,
            action="login",
            target_type="user",
            target_id=user.id,
            metadata={"email": user.email}
        )

        return TokenResponse(access_token=token, user=user)
    finally:
        if conn is not None:
            conn.close()


@router.get("/me", response_model=UserContext)
async def get_me(
    current_user: UserContext = Depends(get_current_user),
) -> UserContext:
    """
    Returns the context of the currently authenticated user.
    Used by the frontend to verify token validity and retrieve user details.
    """
    return current_user
