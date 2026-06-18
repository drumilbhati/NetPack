import os
import sys
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

db_url = os.environ.get("DATABASE_URL")
es_url = os.environ.get("ELASTICSEARCH_URL", "http://localhost:9200")
es_index = os.environ.get("ELASTICSEARCH_INDEX", "netpack-flows")

print(f"DATABASE_URL: {db_url}")
print(f"ELASTICSEARCH_URL: {es_url}")
print(f"ELASTICSEARCH_INDEX: {es_index}")

# Check ES document count
try:
    req = urllib.request.Request(f"{es_url}/{es_index}/_count")
    with urllib.request.urlopen(req) as response:
        res = json.loads(response.read().decode('utf-8'))
        print(f"Elasticsearch document count in index '{es_index}': {res.get('count')}")
except Exception as e:
    print(f"Error querying Elasticsearch count: {e}")

# Check DB evidence_files
try:
    conn = psycopg2.connect(db_url)
    with conn.cursor() as cur:
        cur.execute("SELECT COUNT(*), status FROM evidence_files GROUP BY status")
        rows = cur.fetchall()
        print("Evidence files status in PostgreSQL:")
        for count, status in rows:
            print(f"  - Status: {status}, Count: {count}")
            
        cur.execute("SELECT id, case_id, original_filename, object_key, status, uploaded_by FROM evidence_files LIMIT 10")
        rows = cur.fetchall()
        print("First 10 evidence files:")
        for row in rows:
            print(f"  - ID: {row[0]}, Case ID: {row[1]}, File: {row[2]}, Key: {row[3]}, Status: {row[4]}, Uploaded By: {row[5]}")
    conn.close()
except Exception as e:
    print(f"Error querying DB: {e}")
