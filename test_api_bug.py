import os
import sys
import json
from pathlib import Path
import urllib.request
import urllib.error

# Add project root to sys.path
sys.path.append(os.path.join(os.getcwd(), "backend"))

from app.core.security import create_access_token

def test_api():
    # Create a token for admin@netpack.local
    token = create_access_token({
        "sub": "28145f03-6b01-4ee6-8249-308147b0a697",
        "email": "admin@netpack.local",
        "display_name": "Admin",
        "role": "admin"
    })
    
    import uuid
    import psycopg2
    db_url = os.environ.get("DATABASE_URL", "postgresql://netpack:netpack_dev_password@localhost:5432/netpack")
    conn = psycopg2.connect(db_url)
    cur = conn.cursor()
    cur.execute("SELECT id FROM cases LIMIT 1")
    row = cur.fetchone()
    if row:
        case_id = str(row[0])
    else:
        case_id = str(uuid.uuid4())
        cur.execute(
            "INSERT INTO cases (id, case_number, title, created_by) VALUES (%s, %s, %s, %s)",
            (case_id, "TEST-001", "Test Case", "28145f03-6b01-4ee6-8249-308147b0a697")
        )
        conn.commit()
    conn.close()

    # We must use a valid case in the database to avoid foreign key error
    # Actually, if we just hit /upload with a dummy file, it will fail at DB insert or earlier.
    # Let's see what exception happens. We can use requests if available, or urllib.
    
    boundary = "----WebKitFormBoundary7MA4YWxkTrZu0gW"
    body = (
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="file"; filename="test.pcap"\r\n'
        f"Content-Type: application/vnd.tcpdump.pcap\r\n\r\n"
    ).encode('utf-8') + b"\xa1\xb2\xc3\xd4\x00\x00\x00\x00" + b"\r\n" + f"--{boundary}--\r\n".encode('utf-8')

    req = urllib.request.Request(
        f"http://localhost:8000/api/upload/{case_id}",
        data=body,
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": f"multipart/form-data; boundary={boundary}"
        },
        method="POST"
    )
    
    try:
        response = urllib.request.urlopen(req)
        print("Success:", response.read().decode('utf-8'))
    except urllib.error.HTTPError as e:
        print(f"Failed with {e.code}:")
        print(e.read().decode('utf-8'))
    except Exception as e:
        print("Failed to connect:", e)

if __name__ == "__main__":
    try:
        from dotenv import load_dotenv
        env_path = Path("infra/.env")
        if env_path.exists():
            load_dotenv(env_path)
    except:
        pass
    test_api()
