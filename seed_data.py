#!/usr/bin/env python3
"""
NetPack Database Seed Script
=============================
Seeds the database with large amounts of realistic data for all 3 roles:
  - admin
  - investigator
  - auditor

Designed for load testing with millions of records.

Usage:
    python seed_data.py [--quick] [--full]

Options:
    --quick   Seed a moderate dataset (~50k rows) for functional testing
    --full    Seed a massive dataset (~2M+ rows) for true load testing (default)
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import random
import sys
import time
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

# ── Load env vars from infra/.env ─────────────────────────────────────────────
env_path = Path(__file__).resolve().parent / "infra" / ".env"
if env_path.exists():
    with open(env_path) as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, _, v = line.partition("=")
                os.environ.setdefault(k.strip(), v.strip())

import psycopg2
from psycopg2.extras import execute_values, RealDictCursor

# ── Config ─────────────────────────────────────────────────────────────────────
DB_URL = os.environ.get("DATABASE_URL", "postgresql://netpack:netpack_dev_password@localhost:5432/netpack")

# Shared password hash for all seeded users (plaintext: netpack123)
SHARED_PASSWORD_HASH = "pbkdf2_sha256$310000$5a6f3dcb66d46d9b9d0f9f10e0dc8b91$2090298ca851568e70eb2eb21fd20a989548e8e1b6294e42778fa384fdbf8eb7"

# ── Realistic data pools ────────────────────────────────────────────────────────
FIRST_NAMES = ["Alice","Bob","Carol","David","Eve","Frank","Grace","Henry","Irene","Jack","Karen","Leo","Maria","Nathan","Olivia","Paul","Quinn","Rachel","Sam","Tina","Uma","Victor","Wendy","Xander","Yara","Zoe","Aaron","Beth","Chris","Diana","Ethan","Fiona","George","Hannah","Ivan","Julia","Kevin","Laura","Mike","Nina","Oscar","Petra","Quentin","Rosa","Steve","Tara","Ulric","Vera","Will","Xena"]
LAST_NAMES = ["Smith","Johnson","Williams","Brown","Jones","Garcia","Miller","Davis","Rodriguez","Martinez","Hernandez","Lopez","Gonzalez","Wilson","Anderson","Thomas","Taylor","Moore","Jackson","Martin","Lee","Perez","Thompson","White","Harris","Sanchez","Clark","Ramirez","Lewis","Robinson","Walker","Young","Allen","King","Wright","Scott","Torres","Nguyen","Hill","Flores","Green","Adams","Nelson","Baker","Hall","Rivera","Campbell","Mitchell","Carter","Roberts"]
AGENCIES = ["FBI Cyber Division","CISA","NSA Cybersecurity","DHS","Secret Service","Interpol Cybercrime","Metropolitan Police Cyber Unit","DOJ","ATF Digital","DEA Tech Division","State Police Digital Forensics","US-CERT","NCSC UK","ANSSI France","BSI Germany","ACSC Australia","RCMP Digital Forensics","AFP Cybercrime","AISA","Europol EC3"]
CASE_TITLE_PREFIXES = ["Operation","Investigation","Incident","Analysis","Assessment","Examination","Review","Audit","Monitoring","Surveillance"]
CASE_TITLE_SUBJECTS = ["Dark Web Market Takedown","Ransomware Campaign","DDoS Attribution","C2 Infrastructure","Phishing Kit Distribution","Credential Stuffing Ring","Botnet Mapping","APT Group Activity","Insider Threat","Data Exfiltration","Network Intrusion","Malware Delivery","Spear Phishing","Zero-Day Exploit","Supply Chain Attack","Cryptojacking","Business Email Compromise","Deepfake Detection","Social Engineering","Identity Theft Ring","Skimming Operation","Financial Fraud","Nation-State Attack","Critical Infrastructure Threat","Healthcare Breach","Election Interference","Cryptocurrency Theft","Exploit Kit Distribution","Watering Hole Attack","Man-in-the-Middle","SQL Injection Campaign","Web Shell Deployment","Lateral Movement","Privilege Escalation","Data Destruction"]
ALERT_TITLES = ["Suspicious DNS Query Burst","Lateral Movement Detected","C2 Beacon Pattern","Port Scan Sweep","Data Exfiltration via DNS Tunneling","Brute Force SSH","Unusual Outbound Traffic Volume","TOR Exit Node Communication","Known Malware Hash Match","Protocol Anomaly Detected","Credential Stuffing Attempt","SMB Exploit Attempt","HTTP Flood Detected","ICMP Tunneling Suspected","BGP Route Hijack","Suspicious Certificate Usage","Encrypted C2 Channel","Kerberoasting Attack","Pass-the-Hash Attempt","LLMNR Poisoning","NTLM Relay Attack","ARP Spoofing","VLAN Hopping","Rogue DHCP Server","DNS Cache Poisoning","Reverse Shell Detected","Webshell Activity","Privilege Escalation via SUID","Suspicious Cron Job","Log Tampering Detected"]
ALERT_SOURCES = ["ml_model","rule_engine","signature_match","heuristic","threat_intel"]
SEVERITIES = ["critical","high","medium","low","info"]
ALERT_STATUSES = ["open","investigating","confirmed","false_positive","closed"]
CASE_STATUSES = ["open","closed","archived"]
EVIDENCE_STATUSES = ["registered","parsing","parsed","failed"]
AUDIT_ACTIONS = ["login","logout","view","create","update","delete","upload","download","close_case","update_status","export","generate_report","add_member","remove_member"]
TARGET_TYPES = ["user","case","evidence","alert","report"]
PCAP_FILENAMES = ["capture_{}.pcap","traffic_{}.pcapng","dump_{}.pcap","network_{}.pcapng","evidence_{}.pcap","session_{}.pcap","flow_{}.pcapng","raw_{}.pcap"]
RULE_IDS = ["RULE-ET-001","RULE-ET-002","RULE-ET-003","RULE-NW-001","RULE-NW-002","RULE-ML-001","RULE-ML-002","RULE-TI-001","RULE-TI-002","RULE-TI-003","RULE-SIG-001","RULE-SIG-002","RULE-SIG-003","RULE-HEU-001","RULE-HEU-002","MODEL-LSTM-V2","MODEL-XGB-V1","MODEL-RF-V3","MODEL-CNN-V1","MODEL-BERT-V2"]
EXPLANATIONS_POOL = [
    {
        "reason": "Host exhibiting beaconing behavior with regular intervals of 300 seconds and low jitter.",
        "confidence": 0.85,
        "pattern": "beacon",
        "interval_s": 300,
        "jitter_pct": 5
    },
    {
        "reason": "Suspicious DNS query volume and high payload entropy indicating possible DNS tunneling activity.",
        "confidence": 0.92,
        "pattern": "dns_tunnel",
        "query_count": 1500,
        "entropy": 4.8
    },
    {
        "reason": "Rapid port scanning sweep detected: 65,000 ports probed on a single destination in 12 seconds.",
        "confidence": 0.98,
        "pattern": "port_scan",
        "ports_probed": 65000,
        "duration_s": 12
    },
    {
        "reason": "Large outbound data exfiltration attempt detected: 524 MB of data sent to an external threat intel IP.",
        "confidence": 0.95,
        "pattern": "data_exfil",
        "bytes_sent": 524288000,
        "destination": "185.220.101.45"
    },
    {
        "reason": "Brute force attack on SSH port: 10,000 failed attempts using 9,800 unique passwords.",
        "confidence": 0.99,
        "pattern": "brute_force",
        "attempts": 10000,
        "unique_passwords": 9800
    },
    {
        "reason": "Lateral movement suspected: host initiated unauthorized SMB connections to 23 different internal targets.",
        "confidence": 0.88,
        "pattern": "lateral_move",
        "hosts_touched": 23,
        "protocol": "SMB"
    },
    {
        "reason": "Command & Control connection established: session active to known malicious IP 192.168.1.100 on port 4444.",
        "confidence": 0.97,
        "pattern": "c2_comm",
        "ip": "192.168.1.100",
        "port": 4444
    },
    {
        "reason": "Credential dumping activity: LSASS process memory queried and 127 hashes extracted.",
        "confidence": 0.96,
        "pattern": "credential_dump",
        "hashes_found": 127,
        "method": "LSASS"
    }
]

# ── Helper utilities ────────────────────────────────────────────────────────
def rng_ts(start_days_ago: int = 730, end_days_ago: int = 0) -> datetime:
    now = datetime.now(timezone.utc)
    start = now - timedelta(days=start_days_ago)
    end = now - timedelta(days=end_days_ago)
    return start + timedelta(seconds=random.randint(0, int((end - start).total_seconds())))

def fake_sha256() -> str:
    return hashlib.sha256(uuid.uuid4().bytes).hexdigest()

def fake_badge() -> str:
    return f"B-{random.randint(10000, 99999)}"

def progress(label: str, done: int, total: int) -> None:
    pct = done / total * 100
    bar_len = 40
    filled = int(bar_len * done // total)
    bar = "█" * filled + "░" * (bar_len - filled)
    print(f"\r  [{bar}] {pct:5.1f}%  {label} ({done:,}/{total:,})", end="", flush=True)

# ── Core seeding functions ───────────────────────────────────────────────────
def get_role_ids(conn) -> dict:
    with conn.cursor() as cur:
        cur.execute("SELECT id, name FROM roles")
        return {row["name"]: str(row["id"]) for row in cur.fetchall()}

def get_all_users(conn) -> list:
    with conn.cursor() as cur:
        cur.execute("SELECT u.id, u.email, r.name AS role FROM users u JOIN roles r ON u.role_id = r.id")
        return [dict(r) for r in cur.fetchall()]

def seed_users(conn, role_ids, counts):
    print("\n[1/9] Seeding users...")
    rows = []
    used = set()
    with conn.cursor() as cur:
        cur.execute("SELECT email FROM users")
        for r in cur.fetchall():
            used.add(r["email"])
    for role, cnt in counts.items():
        role_id = role_ids[role]
        for i in range(cnt):
            first = random.choice(FIRST_NAMES)
            last = random.choice(LAST_NAMES)
            suffix = random.randint(100, 99999)
            email = f"{first.lower()}.{last.lower()}{suffix}@netpack.local"
            while email in used:
                suffix += 1
                email = f"{first.lower()}.{last.lower()}{suffix}@netpack.local"
            used.add(email)
            uid = str(uuid.uuid4())
            rows.append((uid, email, f"{first} {last}", role_id, True, SHARED_PASSWORD_HASH, rng_ts(730)))
            if (i+1) % 2000 == 0:
                progress(f"users ({role})", i+1, cnt)
    with conn.cursor() as cur:
        execute_values(cur, "INSERT INTO users (id, email, display_name, role_id, is_active, password_hash, created_at) VALUES %s ON CONFLICT (email) DO NOTHING", rows, page_size=2000)
    conn.commit()
    print(f"\n  ✓ Inserted {len(rows):,} users")

def seed_investigators(conn, users):
    print("\n[2/9] Seeding investigator profiles...")
    inv_users = [u for u in users if u["role"] == "investigator"]
    rows = []
    # Gather existing badge numbers to avoid duplicates
    existing_badges = set()
    with conn.cursor() as cur:
        cur.execute("SELECT badge_number FROM investigators WHERE badge_number IS NOT NULL")
        for r in cur.fetchall():
            existing_badges.add(r["badge_number"])
    for u in inv_users:
        badge = fake_badge()
        # Ensure badge is unique
        while badge in existing_badges:
            badge = fake_badge()
        existing_badges.add(badge)
        rows.append((str(uuid.uuid4()), u["id"], u["email"].split("@")[0].replace(".", " ").title(), u["email"], badge, random.choice(AGENCIES), rng_ts(730)))
    with conn.cursor() as cur:
        execute_values(cur, "INSERT INTO investigators (id, user_id, display_name, email, badge_number, agency, created_at) VALUES %s ON CONFLICT (user_id) DO NOTHING", rows, page_size=500)
    conn.commit()
    print(f"  ✓ Inserted {len(rows):,} investigator profiles")

def seed_cases(conn, users, count):
    print(f"\n[3/9] Seeding {count:,} cases...")
    creators = [u for u in users if u["role"] in ("admin", "investigator")]
    rows = []
    case_ids = []
    seen_numbers = set()
    with conn.cursor() as cur:
        cur.execute("SELECT case_number FROM cases")
        for r in cur.fetchall():
            seen_numbers.add(r["case_number"])
    for i in range(count):
        creator = random.choice(creators)
        case_id = str(uuid.uuid4())
        ts = rng_ts(720)
        num = f"NP-{ts.strftime('%Y%m%d')}-{case_id[:4].upper()}{random.randint(0,99):02d}"
        while num in seen_numbers:
            num = f"NP-{ts.strftime('%Y%m%d')}-{uuid.uuid4().hex[:6].upper()}"
        seen_numbers.add(num)
        title = f"{random.choice(CASE_TITLE_PREFIXES)} {random.choice(CASE_TITLE_SUBJECTS)} #{random.randint(100,9999)}"
        description = f"Full investigation of {title.lower()}."
        status = random.choices(CASE_STATUSES, weights=[60,30,10])[0]
        rows.append((case_id, num, title, description, status, creator["id"], ts, ts))
        case_ids.append({"id": case_id, "created_by": creator["id"], "status": status})
        if (i+1) % 5000 == 0:
            progress("cases", i+1, count)
            with conn.cursor() as cur:
                execute_values(cur, "INSERT INTO cases (id, case_number, title, description, status, created_by, created_at, updated_at) VALUES %s ON CONFLICT (case_number) DO NOTHING", rows, page_size=2000)
            conn.commit()
            rows = []
    if rows:
        with conn.cursor() as cur:
            execute_values(cur, "INSERT INTO cases (id, case_number, title, description, status, created_by, created_at, updated_at) VALUES %s ON CONFLICT (case_number) DO NOTHING", rows, page_size=2000)
        conn.commit()
    print(f"\n  ✓ Inserted {count:,} cases")
    return case_ids

def seed_case_members(conn, cases, users, avg=4):
    print("\n[4/9] Seeding case members...")
    rows = []
    roles = ["owner","analyst","lead","reviewer","observer"]
    for i, case in enumerate(cases):
        n = random.randint(1, avg*2)
        members = random.sample(users, min(n, len(users)))
        for u in members:
            rows.append((case["id"], u["id"], random.choice(roles), rng_ts(700)))
        if len(rows) >= 10000:
            with conn.cursor() as cur:
                execute_values(cur, "INSERT INTO case_members (case_id, user_id, role_name, added_at) VALUES %s ON CONFLICT (case_id, user_id) DO NOTHING", rows, page_size=2000)
            conn.commit()
            rows = []
        if (i+1) % 10000 == 0:
            progress("case_members", i+1, len(cases))
    if rows:
        with conn.cursor() as cur:
            execute_values(cur, "INSERT INTO case_members (case_id, user_id, role_name, added_at) VALUES %s ON CONFLICT (case_id, user_id) DO NOTHING", rows, page_size=2000)
        conn.commit()
    print("\n  ✓ Case members seeded")

def seed_evidence(conn, cases, users, avg=5):
    print("\n[5/9] Seeding evidence files...")
    uploaders = [u for u in users if u["role"] in ("admin", "investigator")]
    rows = []
    ev_list = []
    for i, case in enumerate(cases):
        n = random.randint(1, avg*2)
        used_sha = set()
        for _ in range(n):
            sha = fake_sha256()
            while sha in used_sha:
                sha = fake_sha256()
            used_sha.add(sha)
            ev_id = str(uuid.uuid4())
            fname = random.choice(PCAP_FILENAMES).format(random.randint(1000,9999))
            obj_key = f"evidence/{case['id']}/{ev_id}/{fname}"
            size = random.randint(1024, 100*1024*1024)
            status = random.choices(EVIDENCE_STATUSES, weights=[5,5,80,10])[0]
            uploader = random.choice(uploaders)
            uploaded_at = rng_ts(700)
            parsed_at = uploaded_at + timedelta(minutes=random.randint(1,120)) if status == "parsed" else None
            failure = "Parsing timed out" if status == "failed" else None
            parser_ver = "v1.4.2" if status == "parsed" else None
            rows.append((ev_id, case["id"], fname, obj_key, sha, size, "application/octet-stream", status, parser_ver, uploader["id"], uploaded_at, parsed_at, failure))
            ev_list.append({"id": ev_id, "case_id": case["id"], "status": status})
        if len(rows) >= 5000:
            with conn.cursor() as cur:
                execute_values(cur, "INSERT INTO evidence_files (id, case_id, original_filename, object_key, sha256, byte_size, content_type, status, parser_version, uploaded_by, uploaded_at, parsed_at, failure_reason) VALUES %s ON CONFLICT DO NOTHING", rows, page_size=1000)
            conn.commit()
            rows = []
        if (i+1) % 5000 == 0:
            progress("evidence", i+1, len(cases))
    if rows:
        with conn.cursor() as cur:
            execute_values(cur, "INSERT INTO evidence_files (id, case_id, original_filename, object_key, sha256, byte_size, content_type, status, parser_version, uploaded_by, uploaded_at, parsed_at, failure_reason) VALUES %s ON CONFLICT DO NOTHING", rows, page_size=1000)
        conn.commit()
    print(f"\n  ✓ Inserted {len(ev_list):,} evidence records")
    return ev_list

def seed_alerts(conn, evidence, count):
    print(f"\n[6/9] Seeding {count:,} alerts...")
    parsed = [e for e in evidence if e["status"] == "parsed"] or evidence
    rows = []
    seen = set()
    for i in range(count):
        ev = random.choice(parsed)
        aid = str(uuid.uuid4())
        source = random.choice(ALERT_SOURCES)
        rule = random.choice(RULE_IDS)
        severity = random.choices(SEVERITIES, weights=[5,20,40,25,10])[0]
        status = random.choices(ALERT_STATUSES, weights=[30,20,20,15,15])[0]
        title = random.choice(ALERT_TITLES)
        explanation = json.dumps(random.choice(EXPLANATIONS_POOL))
        flow = json.dumps({
            "src_ip": f"10.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}",
            "dst_ip": f"185.220.{random.randint(100,110)}.{random.randint(1,254)}",
            "src_port": random.randint(1024,65535),
            "dst_port": random.choice([80,443,22,3389,445,8080,4444,1337]),
            "protocol": random.choice(["TCP","UDP","ICMP"]),
            "flow_id": str(uuid.uuid4())
        })
        flow_hash = hashlib.md5(flow.encode()).hexdigest()
        key = (ev["id"], source, rule, flow_hash)
        if key in seen:
            continue
        seen.add(key)
        ts = rng_ts(700)
        rows.append((aid, ev["case_id"], ev["id"], source, rule, "1.0", severity, status, title, explanation, flow, ts, ts))
        if len(rows) >= 5000:
            with conn.cursor() as cur:
                execute_values(cur, "INSERT INTO alerts (id, case_id, evidence_id, source, rule_or_model_id, rule_or_model_version, severity, status, title, explanation, flow_reference, created_at, updated_at) VALUES %s ON CONFLICT DO NOTHING", rows, page_size=1000)
            conn.commit()
            rows = []
        if (i+1) % 50000 == 0:
            progress("alerts", i+1, count)
    if rows:
        with conn.cursor() as cur:
            execute_values(cur, "INSERT INTO alerts (id, case_id, evidence_id, source, rule_or_model_id, rule_or_model_version, severity, status, title, explanation, flow_reference, created_at, updated_at) VALUES %s ON CONFLICT DO NOTHING", rows, page_size=1000)
        conn.commit()
    print(f"\n  ✓ Inserted {len(seen):,} alerts")

def seed_custody(conn, evidence, users, count):
    print(f"\n[7/9] Seeding {count:,} custody events...")
    actions = ["upload","transfer","analysis","review","export","hash_verify","access"]
    rows = []
    for i in range(count):
        ev = random.choice(evidence)
        actor = random.choice(users)
        ce_id = str(uuid.uuid4())
        action = random.choice(actions)
        ts = rng_ts(700)
        details = json.dumps({"action": action, "note": f"Auto event {i}", "workstation": f"WS-{random.randint(100,999)}"})
        rows.append((ce_id, ev["case_id"], ev["id"], actor["id"], action, ts, details))
        if len(rows) >= 5000:
            with conn.cursor() as cur:
                execute_values(cur, "INSERT INTO custody_events (id, case_id, evidence_id, actor_id, action, occurred_at, details) VALUES %s", rows, page_size=1000)
            conn.commit()
            rows = []
        if (i+1) % 100000 == 0:
            progress("custody", i+1, count)
    if rows:
        with conn.cursor() as cur:
            execute_values(cur, "INSERT INTO custody_events (id, case_id, evidence_id, actor_id, action, occurred_at, details) VALUES %s", rows, page_size=1000)
        conn.commit()
    print(f"\n  ✓ Inserted {count:,} custody events")

def seed_audit(conn, users, cases, evidence, count):
    print(f"\n[8/9] Seeding {count:,} audit events (load test)...")
    
    # Map evidence by case_id to avoid O(N) list comprehension inside the loop
    evidence_by_case = {}
    if evidence:
        for ev in evidence:
            evidence_by_case.setdefault(ev["case_id"], []).append(ev)

    rows = []
    for i in range(count):
        actor = random.choice(users)
        action = random.choice(AUDIT_ACTIONS)
        target_type = random.choice(TARGET_TYPES)
        target_id = str(uuid.uuid4())
        case_id = None
        evidence_id = None
        if cases and random.random() < 0.7:
            c = random.choice(cases)
            case_id = c["id"]
            if evidence and target_type == "evidence" and random.random() < 0.5:
                evs = evidence_by_case.get(case_id, [])
                if evs:
                    ev = random.choice(evs)
                    evidence_id = ev["id"]
                    target_id = ev["id"]
        ts = rng_ts(730)
        metadata = json.dumps({"ip": f"10.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}", "ua": random.choice(["Mozilla/5.0","PostmanRuntime/7.32.3","python-requests/2.31.0","curl/7.88.1"]), "duration_ms": random.randint(5,5000)})
        rows.append((str(uuid.uuid4()), actor["id"], actor["role"], action, target_type, target_id, case_id, evidence_id, f"req-{uuid.uuid4().hex[:16]}", ts, metadata))
        if len(rows) >= 5000:
            with conn.cursor() as cur:
                execute_values(cur, "INSERT INTO audit_events (id, actor_id, actor_role, action, target_type, target_id, case_id, evidence_id, request_id, occurred_at, metadata) VALUES %s", rows, page_size=1000)
            conn.commit()
            rows = []
        if (i+1) % 100000 == 0:
            progress("audit", i+1, count)
    if rows:
        with conn.cursor() as cur:
            execute_values(cur, "INSERT INTO audit_events (id, actor_id, actor_role, action, target_type, target_id, case_id, evidence_id, request_id, occurred_at, metadata) VALUES %s", rows, page_size=1000)
        conn.commit()
    print(f"\n  ✓ Inserted {count:,} audit events")

def summary(conn):
    tables = ["roles","users","investigators","cases","case_members","evidence_files","alerts","custody_events","audit_events"]
    print("\n" + "─"*55)
    print("  DATABASE SUMMARY")
    print("─"*55)
    with conn.cursor() as cur:
        for t in tables:
            try:
                cur.execute(f"SELECT COUNT(*) AS c FROM {t}")
                cnt = cur.fetchone()["c"]
                print(f"  {t:<20} {cnt:>12,}")
            except Exception:
                pass
    print("─"*55)

def main():
    parser = argparse.ArgumentParser(description="NetPack DB Seeder")
    parser.add_argument("--quick", action="store_true", help="Seed a modest dataset (~50k rows)")
    parser.add_argument("--full", action="store_true", help="Seed millions of rows (default)")
    args = parser.parse_args()
    mode = "quick" if args.quick else "full"
    if mode == "quick":
        USER_COUNTS = {"admin":20,"investigator":100,"auditor":30}
        CASE_COUNT = 500
        EVIDENCE_AVG = 3
        ALERT_COUNT = 5_000
        CUSTODY_COUNT = 10_000
        AUDIT_COUNT = 50_000
    else:
        USER_COUNTS = {"admin":200,"investigator":2000,"auditor":500}
        CASE_COUNT = 50_000
        EVIDENCE_AVG = 8
        ALERT_COUNT = 1_000_000
        CUSTODY_COUNT = 500_000
        AUDIT_COUNT = 2_000_000
    print("\nConnecting to DB...")
    conn = psycopg2.connect(DB_URL, cursor_factory=RealDictCursor)
    start = time.time()
    try:
        role_ids = get_role_ids(conn)
        seed_users(conn, role_ids, USER_COUNTS)
        all_users = get_all_users(conn)
        seed_investigators(conn, all_users)
        cases = seed_cases(conn, all_users, CASE_COUNT)
        seed_case_members(conn, cases, all_users)
        evidence = seed_evidence(conn, cases, all_users, avg=EVIDENCE_AVG)
        seed_alerts(conn, evidence, ALERT_COUNT)
        seed_custody(conn, evidence, all_users, CUSTODY_COUNT)
        seed_audit(conn, all_users, cases, evidence, AUDIT_COUNT)
    finally:
        elapsed = time.time() - start
        summary(conn)
        print(f"\nTotal time: {elapsed:.1f}s ({elapsed/60:.1f} min)")
        conn.close()
    print("\nSeeding complete. Default password for all seeded accounts: netpack123")

if __name__ == "__main__":
    main()
