import os
import sys
import time
import unittest
import uuid
from pathlib import Path

import psycopg2
from scapy.all import IP, TCP, UDP, Ether, wrpcap

# Add root to sys.path
root_dir = Path(__file__).resolve().parents[2]
sys.path.append(str(root_dir))

# Load environment variables from infra/.env if it exists
try:
    from dotenv import load_dotenv

    load_dotenv(root_dir / "infra" / ".env")
except ImportError:
    pass

from data_processing.index_metadata import request_json
from data_processing.ingestor import EvidenceIngestor


class TestAnomalyIntegration(unittest.TestCase):
    def setUp(self):
        self.db_url = os.environ.get(
            "DATABASE_URL",
            "postgresql://netpack:netpack_dev_password@localhost:5432/netpack",
        )
        self.pcap_path = Path("anomaly_test.pcap")
        self.generate_pcap()
        self.ingestor = EvidenceIngestor()
        self.setup_db()

    def setup_db(self):
        """Ensure a test case and user exist in the DB."""
        conn = psycopg2.connect(self.db_url)
        try:
            with conn.cursor() as cur:
                # 1. Ensure a role exists
                cur.execute(
                    "INSERT INTO roles (name) VALUES ('investigator') ON CONFLICT (name) DO NOTHING"
                )
                cur.execute("SELECT id FROM roles WHERE name = 'investigator'")
                role_id = cur.fetchone()[0]

                # 2. Ensure a user exists
                cur.execute("SELECT id FROM users WHERE email = 'test@example.com'")
                res = cur.fetchone()
                if res:
                    self.user_id = res[0]
                else:
                    self.user_id = str(uuid.uuid4())
                    cur.execute(
                        "INSERT INTO users (id, email, display_name, role_id) VALUES (%s, %s, %s, %s)",
                        (self.user_id, "test@example.com", "Test User", role_id),
                    )

                # 3. Ensure a case exists
                self.case_id = str(uuid.uuid4())
                cur.execute(
                    "INSERT INTO cases (id, case_number, title, created_by) VALUES (%s, %s, %s, %s)",
                    (
                        self.case_id,
                        f"TEST-{int(time.time())}",
                        "Anomaly Test Case",
                        self.user_id,
                    ),
                )
            conn.commit()
        finally:
            conn.close()

    def generate_pcap(self):
        """Generate a PCAP with normal and anomalous traffic."""
        packets = []

        # 1. Normal Traffic: Small packets, few count
        for i in range(5):
            p = (
                Ether()
                / IP(src="192.168.1.10", dst="8.8.8.8")
                / TCP(sport=12345, dport=80)
                / "Normal"
            )
            packets.append(p)

        # 2. Anomalous Traffic: Large packets, many count (Exfiltration)
        for i in range(100):
            p = (
                Ether()
                / IP(src="192.168.1.50", dst="99.99.99.99")
                / TCP(sport=54321, dport=443)
                / ("ANOMALY" * 100)
            )
            packets.append(p)

        wrpcap(str(self.pcap_path), packets)
        print(f"Generated {self.pcap_path}")

    def test_ingestion_and_anomaly_detection(self):
        from data_processing.ingestor import ML_READY

        if not ML_READY:
            self.skipTest("ML model or dependencies not available")

        evidence_id = self.ingestor.ingest(
            case_id=self.case_id, file_path=self.pcap_path, uploaded_by=self.user_id
        )

        print(f"Ingested evidence: {evidence_id}")

        # Wait for ES to refresh
        time.sleep(2)

        # Query ES for anomalies in this evidence
        es_url = self.ingestor.es_url
        index = self.ingestor.es_index

        query = {
            "query": {
                "bool": {
                    "must": [
                        {"term": {"evidence_id": evidence_id}},
                        {"term": {"is_anomaly": True}},
                    ]
                }
            }
        }

        response = request_json("POST", f"{es_url}/{index}/_search", query)
        hits = response.get("hits", {}).get("hits", [])

        print(f"Found {len(hits)} anomalies in Elasticsearch.")

        # Verify that the exfiltration flow was flagged
        flagged_ips = [h["_source"]["destination_ip"] for h in hits]
        self.assertIn("99.99.99.99", flagged_ips)

        # Verify that the normal flow was NOT flagged as anomaly
        query_normal = {
            "query": {
                "bool": {
                    "must": [
                        {"term": {"evidence_id": evidence_id}},
                        {"term": {"destination_ip": "8.8.8.8"}},
                        {"term": {"is_anomaly": True}},
                    ]
                }
            }
        }
        response_normal = request_json(
            "POST", f"{es_url}/{index}/_search", query_normal
        )
        self.assertEqual(response_normal["hits"]["total"]["value"], 0)

        # Verify alerts in PostgreSQL
        conn = psycopg2.connect(self.db_url)
        try:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT source, rule_or_model_id FROM alerts WHERE evidence_id = %s",
                    (evidence_id,),
                )
                alerts = cur.fetchall()
                print(f"Found {len(alerts)} alerts in DB: {alerts}")

                # Should have at least one ML alert for the anomaly
                sources = [a[0] for a in alerts]
                self.assertIn("ML", sources)
        finally:
            conn.close()

    def tearDown(self):
        if self.pcap_path.exists():
            self.pcap_path.unlink()

        # Cleanup DB records
        if hasattr(self, "case_id"):
            conn = psycopg2.connect(self.db_url)
            try:
                with conn.cursor() as cur:
                    cur.execute(
                        "DELETE FROM custody_events WHERE case_id = %s", (self.case_id,)
                    )
                    cur.execute(
                        "DELETE FROM audit_events WHERE case_id = %s", (self.case_id,)
                    )
                    cur.execute(
                        "DELETE FROM evidence_files WHERE case_id = %s", (self.case_id,)
                    )
                    cur.execute("DELETE FROM cases WHERE id = %s", (self.case_id,))
                conn.commit()
            finally:
                conn.close()


if __name__ == "__main__":
    unittest.main()
