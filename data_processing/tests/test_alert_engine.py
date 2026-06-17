import os
import unittest
from unittest.mock import MagicMock, patch

from data_processing.threat_detection_service import ThreatDetectionService


def ipv4(*octets: int) -> str:
    return ".".join(str(octet) for octet in octets)


FLOW_SRC_IP = ipv4(10, 0, 0, 5)
FLOW_DST_IP_A = ipv4(8, 8, 8, 8)
PORT_SCAN_SRC_IP = ipv4(1, 1, 1, 1)
PORT_SCAN_DST_IP = ipv4(2, 2, 2, 2)


class TestThreatDetectionService(unittest.TestCase):
    @patch("psycopg2.connect")
    def test_process_evidence(self, mock_connect):
        service = ThreatDetectionService(db_url="mock_db_url")
        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_connect.return_value = mock_conn
        mock_conn.cursor.return_value.__enter__.return_value = mock_cursor
        mock_cursor.fetchone.return_value = (1,)  # Simulate successful insert

        case_id = "test-case-uuid"
        evidence_id = "test-evidence-uuid"

        packet_records = [
            {
                "dns_query": "malicious.xyz",
                "source_ip": FLOW_SRC_IP,
                "timestamp": "2023-01-01T12:00:00Z",
            }
        ]

        flow_records = [
            {
                "is_anomaly": True,
                "anomaly_score": -0.2,
                "source_ip": FLOW_SRC_IP,
                "destination_ip": FLOW_DST_IP_A,
                "source_port": 12345,
                "destination_port": 53,
                "protocol": "UDP",
                "bytes_sent": 60 * 1024 * 1024,  # > 50MB
                "bytes_received": 100,
                "packet_count": 50,
                "duration": 5.0,
                "timestamp": "2023-01-01T12:00:00Z",
            }
        ]

        count = service.process_evidence(
            case_id, evidence_id, packet_records, flow_records
        )

        # 1 ML alert, 1 EXFIL_HIGH_VOLUME alert, 1 SUSPICIOUS_DNS_TLD alert
        self.assertEqual(count, 3)
        self.assertEqual(mock_cursor.execute.call_count, 3)

    def test_port_scanning_rule(self):
        service = ThreatDetectionService(db_url=None)  # No DB for logic test

        case_id = "test-case-uuid"
        evidence_id = "test-evidence-uuid"

        # Generate 25 flows to different ports from same src
        flow_records = []
        for p in range(25):
            flow_records.append(
                {
                    "source_ip": PORT_SCAN_SRC_IP,
                    "destination_ip": PORT_SCAN_DST_IP,
                    "destination_port": 1000 + p,
                    "protocol": "TCP",
                    "bytes_sent": 100,
                    "timestamp": "2023-01-01T12:00:00Z",
                }
            )

        alerts = service._run_signature_rules(
            flow_records, [], {"case_id": case_id, "evidence_id": evidence_id}
        )

        # Should have PORT_SCANNING alert
        ids = [a["rule_or_model_id"] for a in alerts]
        self.assertIn("PORT_SCANNING", ids)


if __name__ == "__main__":
    unittest.main()
