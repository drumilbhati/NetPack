from datetime import datetime, timezone
from typing import List

from fastapi import APIRouter

from app.schemas.case import Case, CaseCreate

router = APIRouter()

# In-memory storage for demonstration purposes
mock_cases = []
case_id_counter = 1


@router.post("/", response_model=Case)
async def create_case(case_in: CaseCreate):
    global case_id_counter
    new_case = Case(
        id=case_id_counter,
        title=case_in.title,
        description=case_in.description,
        created_at=datetime.now(timezone.utc),
    )
    mock_cases.append(new_case)
    case_id_counter += 1
    return new_case


@router.get("/", response_model=List[Case])
async def list_cases():
    return mock_cases
