import unittest
import os
import httpx
from fastapi.testclient import TestClient
from app.main import app

# Ensure we use the local ES
os.environ["ELASTICSEARCH_URL"] = "http://localhost:9200"


def ipv4(*octets: int) -> str:
    return ".".join(str(octet) for octet in octets)


SOURCE_IP = ipv4(10, 10, 1, 15)
DEST_IP_A = ipv4(198, 51, 100, 25)
DEST_IP_B = ipv4(8, 8, 8, 8)
NO_MATCH_IP = ipv4(1, 2, 3, 4)

class TestSearchIntegration(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(app)
        cls.es_url = os.environ.get("ELASTICSEARCH_URL", "http://localhost:9200").rstrip("/")
        cls.index = "netpack-flows"
        
        mapping = {
            "mappings": {
                "properties": {
                    "case_id": {"type": "keyword"},
                    "evidence_id": {"type": "keyword"},
                    "sha256": {"type": "keyword"},
                    "source_ip": {"type": "ip"},
                    "destination_ip": {"type": "ip"},
                    "source_port": {"type": "integer"},
                    "destination_port": {"type": "integer"},
                    "protocol": {"type": "keyword"},
                    "timestamp": {"type": "date", "ignore_malformed": True},
                    "metadata": {"type": "object", "enabled": True},
                }
            }
        }
        
        # Seed test data
        test_data = [
            {
                "timestamp": "2026-06-12T10:00:00Z",
                "source_ip": SOURCE_IP,
                "destination_ip": DEST_IP_A,
                "source_port": 49152,
                "destination_port": 443,
                "protocol": "TCP",
                "metadata": {},
            },
            {
                "timestamp": "2026-06-12T10:00:02Z",
                "source_ip": SOURCE_IP,
                "destination_ip": DEST_IP_B,
                "source_port": 53000,
                "destination_port": 53,
                "protocol": "UDP",
                "metadata": {},
            },
        ]
        
        with httpx.Client() as es_client:
            # Ensure a clean state, ignoring 404 if index doesn't exist
            try:
                es_client.delete(f"{cls.es_url}/{cls.index}")
            except httpx.HTTPStatusError as e:
                if e.response.status_code != 404:
                    raise
            
            # Create index with mapping
            resp = es_client.put(f"{cls.es_url}/{cls.index}", json=mapping)
            resp.raise_for_status()
            
            for doc in test_data:
                resp = es_client.post(f"{cls.es_url}/{cls.index}/_doc?refresh=wait_for", json=doc)
                resp.raise_for_status()

    @classmethod
    def tearDownClass(cls):
        es_url = os.environ.get("ELASTICSEARCH_URL", "http://localhost:9200").rstrip("/")
        index = "netpack-flows"
        with httpx.Client() as es_client:
            try:
                es_client.delete(f"{es_url}/{index}")
            except httpx.HTTPStatusError as e:
                if e.response.status_code != 404:
                    raise
            except Exception:
                pass

    def test_search_real_ip(self):
        response = self.client.get(f"/search?source_ip={SOURCE_IP}")
        
        self.assertEqual(response.status_code, 200)
        results = response.json()
        self.assertEqual(len(results), 2)
        self.assertEqual(results[0]["source_ip"], SOURCE_IP)

    def test_search_protocol(self):
        response = self.client.get("/search?protocol=UDP")
        
        self.assertEqual(response.status_code, 200)
        results = response.json()
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["protocol"], "UDP")

    def test_search_no_results(self):
        response = self.client.get(f"/search?source_ip={NO_MATCH_IP}")
        
        self.assertEqual(response.status_code, 200)
        results = response.json()
        self.assertEqual(len(results), 0)

    def test_search_time_range(self):
        response = self.client.get("/search?time_range=2026-06-12T00:00:00Z,2026-06-13T00:00:00Z")
        
        self.assertEqual(response.status_code, 200)
        results = response.json()
        self.assertEqual(len(results), 2)

if __name__ == "__main__":
    unittest.main()
