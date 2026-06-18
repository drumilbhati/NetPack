import os
import sys
import uuid
from pathlib import Path
import psycopg2
import json

# Add project root to sys.path
sys.path.append(os.getcwd())
from dotenv import load_dotenv

env_path = Path("infra/.env")
if env_path.exists():
    load_dotenv(env_path)

db_url = os.environ.get("DATABASE_URL")
conn = psycopg2.connect(db_url)

try:
    case_id = str(uuid.uuid4())
    user_id = str(uuid.uuid4())
    evidence_id = str(uuid.uuid4())
    sha256 = "a" * 64
    size = 100
    
    with conn.cursor() as cur:
        # Create a dummy user
        cur.execute("INSERT INTO roles (name) VALUES ('admin_test') ON CONFLICT DO NOTHING")
        cur.execute("SELECT id FROM roles WHERE name = 'admin_test'")
        role_id = cur.fetchone()[0]
        
        cur.execute(
            "INSERT INTO users (id, email, display_name, role_id) VALUES (%s, %s, %s, %s) ON CONFLICT DO NOTHING",
            (user_id, f"{user_id}@test.com", "Test", role_id)
        )
        
        # Create a dummy case
        cur.execute(
            "INSERT INTO cases (id, case_number, title, created_by) VALUES (%s, %s, %s, %s)",
            (case_id, case_id[:8], "Test Case", user_id)
        )
        
        print("Inserting evidence_files...")
        cur.execute(
            """
            INSERT INTO evidence_files (id, case_id, original_filename, object_key, sha256, byte_size, status, uploaded_by)
            VALUES (%s, %s, %s, %s, %s, %s, 'registered', %s)
            RETURNING id
            """,
            (
                evidence_id,
                case_id,
                "test.pcap",
                "uploads/test.pcap",
                sha256,
                size,
                user_id,
            ),
        )
        returned_evidence_id = cur.fetchone()[0]
        print(f"Evidence ID: {returned_evidence_id}")

        print("Inserting custody_events...")
        cur.execute(
            """
            INSERT INTO custody_events (case_id, evidence_id, actor_id, action, details)
            VALUES (%s, %s, %s, 'upload', %s)
            """,
            (
                case_id,
                returned_evidence_id,
                user_id,
                json.dumps({"filename": "test.pcap"}),
            ),
        )
        print("Done!")
except Exception as e:
    import traceback
    traceback.print_exc()
finally:
    conn.rollback()
    conn.close()
