#!/usr/bin/env python3
import os
import sys
import random
import uuid
import datetime
from pathlib import Path
import psycopg2
from psycopg2.extras import RealDictCursor

# Load env variables from infra/.env
env_path = Path(__file__).resolve().parent / "infra" / ".env"
if env_path.exists():
    with open(env_path) as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, _, v = line.partition("=")
                os.environ.setdefault(k.strip(), v.strip())

# Setup python path to import from data_processing
sys.path.append(os.getcwd())
from data_processing.index_metadata import index_records

DATABASE_URL = os.environ.get("DATABASE_URL", "postgresql://netpack:netpack_dev_password@localhost:5432/netpack")
ELASTICSEARCH_URL = os.environ.get("ELASTICSEARCH_URL", "http://localhost:9200")
ELASTICSEARCH_INDEX = os.environ.get("ELASTICSEARCH_INDEX", "netpack-flows")

def generate_flows():
    print("Connecting to PostgreSQL to fetch cases and evidence...")
    conn = psycopg2.connect(DATABASE_URL, cursor_factory=RealDictCursor)
    cur = conn.cursor()
    
    # Let's fetch 500 cases that have evidence files
    cur.execute("""
        SELECT DISTINCT c.id as case_id 
        FROM cases c
        JOIN evidence_files e ON c.id = e.case_id
        WHERE e.status = 'parsed'
        LIMIT 200
    """)
    cases = cur.fetchall()
    print(f"Found {len(cases)} cases with parsed evidence files.")
    
    if not cases:
        print("No cases with parsed evidence files found. Fetching any cases...")
        cur.execute("SELECT id as case_id FROM cases LIMIT 200")
        cases = cur.fetchall()
        
    if not cases:
        print("No cases found in DB. Seeding cannot proceed.")
        return
        
    case_ids = [c["case_id"] for c in cases]
    
    # Fetch evidence files for these cases
    cur.execute("""
        SELECT id, case_id::text, sha256 
        FROM evidence_files 
        WHERE case_id::text = ANY(%s) 
        LIMIT 1000
    """, (case_ids,))
    evidence_files = cur.fetchall()
    print(f"Found {len(evidence_files)} evidence files to generate flows for.")
    
    cur.close()
    conn.close()
    
    if not evidence_files:
        print("No evidence files found in DB.")
        return

    # Pools of realistic IPs
    internal_ips = [f"10.10.1.{i}" for i in range(2, 254)] + [f"10.10.2.{i}" for i in range(2, 254)]
    external_ips = [f"198.51.100.{i}" for i in range(2, 254)] + [f"203.0.113.{i}" for i in range(2, 254)]
    protocols = ["TCP", "UDP", "ICMP"]
    
    # Generate around 15,000 flows
    records = []
    total_flows = 15000
    now = datetime.datetime.now(datetime.timezone.utc)
    
    # Malicious IPs that will show up as red (anomalous) on the graph
    malicious_internal = ["10.10.1.99", "10.10.2.50", "10.10.2.200"]
    malicious_external = ["198.51.100.66", "203.0.113.99"]
    
    print(f"Generating {total_flows} flow records...")
    for i in range(total_flows):
        ev = random.choice(evidence_files)
        protocol = random.choice(protocols)
        
        # Determine ports
        if protocol == "ICMP":
            src_port = None
            dst_port = None
        else:
            src_port = random.randint(1024, 65535)
            dst_port = random.choice([80, 443, 22, 53, 8080, 445])
            
        # 1.5% chance of generating a malicious flow which is marked as anomalous
        if random.random() < 0.015:
            src_ip = random.choice(malicious_internal)
            dst_ip = random.choice(malicious_external)
            is_anomaly = True
        else:
            src_ip = random.choice(internal_ips)
            dst_ip = random.choice(external_ips)
            is_anomaly = False
            
        anomaly_score = random.uniform(0.75, 0.99) if is_anomaly else random.uniform(0.01, 0.15)
        
        # Timestamp distributed in the last 30 days
        days_ago = random.uniform(0, 30)
        ts = now - datetime.timedelta(days=days_ago)
        
        # Bytes sent/received
        bytes_sent = random.randint(500, 100 * 1024 * 1024)  # 500B to 100MB
        bytes_received = random.randint(500, 500 * 1024 * 1024)  # 500B to 500MB
        
        record = {
            "case_id": ev["case_id"],
            "evidence_id": ev["id"],
            "sha256": ev["sha256"],
            "source_ip": src_ip,
            "destination_ip": dst_ip,
            "source_port": src_port,
            "destination_port": dst_port,
            "protocol": protocol,
            "timestamp": ts.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z",
            "bytes_sent": bytes_sent,
            "bytes_received": bytes_received,
            "duration": float(f"{random.uniform(0.05, 60.0):.3f}"),
            "packet_count": random.randint(5, 5000),
            "is_anomaly": is_anomaly,
            "anomaly_score": float(f"{anomaly_score:.3f}"),
            "metadata": {}
        }
        records.append(record)
        
    print(f"Indexing generated flows into Elasticsearch at {ELASTICSEARCH_URL} index '{ELASTICSEARCH_INDEX}'...")
    try:
        index_records(records, ELASTICSEARCH_URL, ELASTICSEARCH_INDEX)
        print("Successfully indexed flow records!")
    except Exception as e:
        print(f"Failed to index flow records: {e}")

if __name__ == "__main__":
    generate_flows()
