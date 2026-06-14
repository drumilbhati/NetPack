import unittest
import os
import httpx
from fastapi.testclient import TestClient
from app.main import app

# Ensure we use the local ES
os.environ["ELASTICSEARCH_URL"] = "http://localhost:9200"

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
                "source_ip": "10.10.1.15",
                "destination_ip": "198.51.100.25",
                "source_port": 49152,
                "destination_port": 443,
                "protocol": "TCP",
                "metadata": {}
            },
            {
                "timestamp": "2026-06-12T10:00:02Z",
                "source_ip": "10.10.1.15",
                "destination_ip": "8.8.8.8",
                "source_port": 53000,
                "destination_port": 53,
                "protocol": "UDP",
                "metadata": {}
            }
        ]
        
        with httpx.Client() as es_client:
            # Ensure a clean state
            es_client.delete(f"{cls.es_url}/{cls.index}")
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
            es_client.delete(f"{es_url}/{index}")

    def test_search_real_ip(self):
        # From seeded data: 10.10.1.15
        response = self.client.get("/search?source_ip=10.10.1.15")
        
        self.assertEqual(response.status_code, 200)
        results = response.json()
        self.assertEqual(len(results), 2)
        self.assertEqual(results[0]["source_ip"], "10.10.1.15")

    def test_search_protocol(self):
        response = self.client.get("/search?protocol=UDP")
        
        self.assertEqual(response.status_code, 200)
        results = response.json()
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["protocol"], "UDP")

    def test_search_no_results(self):
        response = self.client.get("/search?source_ip=1.2.3.4")
        
        self.assertEqual(response.status_code, 200)
        results = response.json()
        self.assertEqual(len(results), 0)

    def test_search_time_range(self):
        # Range covering the sample timestamps (2026-06-12)
        response = self.client.get("/search?time_range=2026-06-12T00:00:00Z,2026-06-13T00:00:00Z")
        
        self.assertEqual(response.status_code, 200)
        results = response.json()
        self.assertEqual(len(results), 2)

if __name__ == "__main__":
    unittest.main()
