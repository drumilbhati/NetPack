from datetime import datetime
from typing import Any, Dict, List, Optional

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
    http_host: Optional[str] = None
    tls_sni: Optional[str] = None
    dns_query: Optional[str] = None
    ftp_command: Optional[str] = None
    smtp_command: Optional[str] = None
    smb_command: Optional[str] = None
    payload_signatures: Optional[List[str]] = None
    bytes_sent: Optional[int] = None
    bytes_received: Optional[int] = None
    duration: Optional[float] = None
    packet_count: Optional[int] = None
    anomaly_score: Optional[float] = None
    is_anomaly: Optional[bool] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)
