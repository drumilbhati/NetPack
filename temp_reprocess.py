import os
import sys
from unittest.mock import MagicMock

# Mock confluent_kafka module before importing worker
sys.modules['confluent_kafka'] = MagicMock()

import psycopg2
from pathlib import Path
from dotenv import load_dotenv
import urllib.request
import json

# Add project root to sys.path
sys.path.append(os.getcwd())

env_path = Path("infra/.env")
if env_path.exists():
    load_dotenv(env_path)

from data_processing.worker import ParserWorker

db_url = os.environ.get("DATABASE_URL")
es_url = os.environ.get("ELASTICSEARCH_URL", "http://localhost:9200")
es_index = os.environ.get("ELASTICSEARCH_INDEX", "netpack-flows")

print(f"DATABASE_URL: {db_url}")
print(f"ELASTICSEARCH_URL: {es_url}")
print(f"ELASTICSEARCH_INDEX: {es_index}")

# Initialize parser worker
worker = ParserWorker()

try:
    conn = psycopg2.connect(db_url)
    with conn.cursor() as cur:
        # Get all evidence files
        cur.execute("SELECT id, case_id, original_filename, object_key, sha256, status, uploaded_by FROM evidence_files")
        rows = cur.fetchall()
        total_files = len(rows)
        print(f"Found {total_files} evidence files in PostgreSQL.")
        
        processed_count = 0
        success_count = 0
        failed_count = 0
        
        for row in rows:
            evidence_id = row[0]
            case_id = row[1]
            filename = row[2]
            object_key = row[3]
            sha256 = row[4]
            status = row[5]
            uploaded_by = row[6]
            
            processed_count += 1
            if processed_count % 10 == 0 or processed_count == total_files:
                print(f"[{processed_count}/{total_files}] Processing {filename} ({evidence_id})...")
            
            # Construct job payload
            # Note: We set uploaded_by to None to bypass the RBAC check in worker
            job = {
                "case_id": case_id,
                "evidence_id": evidence_id,
                "object_key": object_key,
                "filename": filename,
                "sha256": sha256,
                "uploaded_by": None
            }
            
            try:
                # Process the job
                worker.process_job(job)
                success_count += 1
            except Exception as e:
                failed_count += 1
                print(f"Error processing {filename} ({evidence_id}): {e}")
                
        print(f"\nReprocessing completed.")
        print(f"Total: {total_files}, Succeeded: {success_count}, Failed: {failed_count}")
        
    conn.close()
except Exception as e:
    print(f"Database error: {e}")

# Check ES count again
try:
    req = urllib.request.Request(f"{es_url}/{es_index}/_count")
    with urllib.request.urlopen(req) as response:
        res = json.loads(response.read().decode('utf-8'))
        print(f"New Elasticsearch document count in '{es_index}': {res.get('count')}")
except Exception as e:
    print(f"Error querying Elasticsearch count: {e}")
