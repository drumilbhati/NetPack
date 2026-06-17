from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
from datetime import datetime, timedelta, timezone
from typing import Any, Dict

from fastapi import HTTPException, status

JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY", "netpack-dev-secret-change-me")
JWT_ALGORITHM = os.getenv("JWT_ALGORITHM", "HS256")
JWT_EXPIRES_MINUTES = int(os.getenv("JWT_EXPIRES_MINUTES", "480"))
PASSWORD_HASH_ITERATIONS = int(os.getenv("PASSWORD_HASH_ITERATIONS", "310000"))
PASSWORD_HASH_NAME = "pbkdf2_sha256"


def _b64url_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _b64url_decode(value: str) -> bytes:
    padding = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(value + padding)


def hash_password(password: str, salt: bytes | None = None) -> str:
    salt_bytes = salt or secrets.token_bytes(16)
    derived = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt_bytes, PASSWORD_HASH_ITERATIONS
    )
    return (
        f"{PASSWORD_HASH_NAME}${PASSWORD_HASH_ITERATIONS}$"
        f"{salt_bytes.hex()}${derived.hex()}"
    )


def verify_password(password: str, stored_hash: str) -> bool:
    try:
        algorithm, iterations, salt_hex, digest_hex = stored_hash.split("$")
        if algorithm != PASSWORD_HASH_NAME:
            return False
        iterations_int = int(iterations)
        salt_bytes = bytes.fromhex(salt_hex)
        expected = bytes.fromhex(digest_hex)
        candidate = hashlib.pbkdf2_hmac(
            "sha256", password.encode("utf-8"), salt_bytes, iterations_int
        )
        return hmac.compare_digest(candidate, expected)
    except Exception:
        return False


def _sign(message: bytes) -> bytes:
    return hmac.new(JWT_SECRET_KEY.encode("utf-8"), message, hashlib.sha256).digest()


def create_access_token(claims: Dict[str, Any]) -> str:
    now = datetime.now(timezone.utc)
    payload = {
        **claims,
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(minutes=JWT_EXPIRES_MINUTES)).timestamp()),
    }
    header = {"alg": JWT_ALGORITHM, "typ": "JWT"}
    header_segment = _b64url_encode(
        json.dumps(header, separators=(",", ":")).encode("utf-8")
    )
    payload_segment = _b64url_encode(
        json.dumps(payload, separators=(",", ":")).encode("utf-8")
    )
    signing_input = f"{header_segment}.{payload_segment}".encode("utf-8")
    signature = _b64url_encode(_sign(signing_input))
    return f"{header_segment}.{payload_segment}.{signature}"


def decode_access_token(token: str) -> Dict[str, Any]:
    try:
        header_segment, payload_segment, signature_segment = token.split(".")
        signing_input = f"{header_segment}.{payload_segment}".encode("utf-8")
        expected_signature = _b64url_encode(_sign(signing_input))
        if not hmac.compare_digest(signature_segment, expected_signature):
            raise ValueError("Invalid token signature")

        header = json.loads(_b64url_decode(header_segment).decode("utf-8"))
        if header.get("alg") != JWT_ALGORITHM:
            raise ValueError("Unsupported token algorithm")

        payload = json.loads(_b64url_decode(payload_segment).decode("utf-8"))
        if not isinstance(payload, dict):
            raise ValueError("Invalid token payload")

        exp = payload.get("exp")
        if isinstance(exp, int) and exp < int(datetime.now(timezone.utc).timestamp()):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Token has expired",
            )

        return payload
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication token",
        ) from exc
