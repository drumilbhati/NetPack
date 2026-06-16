import uuid
from datetime import datetime, timezone
from typing import List

from fastapi import APIRouter

from app.schemas.case import Case, CaseCreate

router = APIRouter()

# In-memory storage for demonstration purposes
mock_cases = []


@router.post("/", response_model=Case)
async def create_case(case_in: CaseCreate):
    new_case = Case(
        id=str(uuid.uuid4()),
        title=case_in.title,
        description=case_in.description,
        created_at=datetime.now(timezone.utc),
    )
    mock_cases.append(new_case)
    return new_case


@router.get("/", response_model=List[Case])
async def list_cases():
    return mock_cases
