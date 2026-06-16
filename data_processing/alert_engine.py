from typing import Any, Dict, List, Optional

from .threat_detection_service import ThreatDetectionService


class AlertEngine:
    """
    Legacy wrapper for ThreatDetectionService.
    """

    def __init__(self, db_url: Optional[str] = None):
        self.service = ThreatDetectionService(db_url=db_url)

    def process_and_store_alerts(
        self,
        packet_records: List[Dict[str, Any]],
        flow_records: List[Dict[str, Any]],
        context: Dict[str, Any],
    ):
        """
        Process records against rules and ML results, then store in Postgres.
        """
        self.service.process_evidence(
            case_id=context["case_id"],
            evidence_id=context["evidence_id"],
            packet_records=packet_records,
            flow_records=flow_records,
        )
