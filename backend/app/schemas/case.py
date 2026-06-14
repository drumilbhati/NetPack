from pydantic import BaseModel, ConfigDict
from datetime import datetime
from typing import Optional, List

class CaseBase(BaseModel):
    title: str
    description: Optional[str] = None

class CaseCreate(CaseBase):
    pass

class Case(CaseBase):
    id: int
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)
