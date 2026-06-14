import unittest
import time
import os
from fastapi.testclient import TestClient
from app.main import app

# Ensure we use the local ES
os.environ["ELASTICSEARCH_URL"] = "http://localhost:9200"

class TestSearchIntegration(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(app)
        # Give ES a moment to ensure indices are refreshed if needed 
        # (though index_metadata.py uses refresh=wait_for)
        time.sleep(1)

    def test_search_real_ip(self):
        # From sample_metadata.json: 10.10.1.15
        response = self.client.get("/search?source_ip=10.10.1.15")
        
        self.assertEqual(response.status_code, 200)
        results = response.json()
        self.assertGreaterEqual(len(results), 2) # There are 2 records with this source_ip in sample
        self.assertEqual(results[0]["source_ip"], "10.10.1.15")

    def test_search_protocol(self):
        response = self.client.get("/search?protocol=UDP")
        
        self.assertEqual(response.status_code, 200)
        results = response.json()
        self.assertGreaterEqual(len(results), 1)
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
        self.assertGreaterEqual(len(results), 2)

if __name__ == "__main__":
    unittest.main()
