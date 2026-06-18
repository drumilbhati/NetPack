import pytest
from app.core.security import create_access_token, decode_access_token, hash_password, verify_password

def test_password_hashing():
    password = "secure-password-123"
    hashed = hash_password(password)
    assert hashed != password
    assert verify_password(password, hashed) is True
    assert verify_password("wrong-password", hashed) is False

def test_jwt_token_flow():
    claims = {
        "sub": "user-uuid-1234",
        "email": "investigator@netpack.local",
        "role": "investigator"
    }
    token = create_access_token(claims)
    assert isinstance(token, str)
    
    decoded = decode_access_token(token)
    assert decoded["sub"] == claims["sub"]
    assert decoded["email"] == claims["email"]
    assert decoded["role"] == claims["role"]
    assert "exp" in decoded
    assert "iat" in decoded

def test_invalid_token():
    with pytest.raises(Exception): # PyJWTError or HTTPException
        decode_access_token("invalid.token.here")
