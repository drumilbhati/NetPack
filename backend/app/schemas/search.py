from datetime import datetime
from typing import Any, Dict, Optional

from pydantic import BaseModel, Field


class PacketMetadata(BaseModel):
    case_id: Optional[str] = None
    evidence_id: Optional[str] = None
    sha256: Optional[str] = None
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    source_port: Optional[int] = None
    destination_port: Optional[int] = None
    protocol: Optional[str] = None
    timestamp: Optional[datetime] = None
    http_url: Optional[str] = None
    http_user_agent: Optional[str] = None
    dns_query: Optional[str] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)
