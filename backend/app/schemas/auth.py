from typing import Optional

from pydantic import BaseModel


class LoginRequest(BaseModel):
    email: str
    password: str


class UserContext(BaseModel):
    id: str
    email: str
    display_name: str
    role: str
    is_active: bool = True


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user: UserContext


class RoleContext(BaseModel):
    name: str
    description: Optional[str] = None
