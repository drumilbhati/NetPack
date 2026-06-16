from typing import List, Optional
from pydantic import BaseModel


class GraphNode(BaseModel):
    id: str
    label: str
    color: Optional[str] = "#2563eb"


class GraphLink(BaseModel):
    source: str
    target: str


class GraphResponse(BaseModel):
    nodes: List[GraphNode]
    links: List[GraphLink]
