from datetime import datetime
from typing import Optional

from pydantic import BaseModel, ConfigDict


class CaseBase(BaseModel):
    title: str
    description: Optional[str] = None


class CaseCreate(CaseBase):
    pass


class Case(CaseBase):
    id: str
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)
