import os
import sys
from pathlib import Path
import psycopg2

sys.path.append(os.getcwd())
from dotenv import load_dotenv

env_path = Path("infra/.env")
if env_path.exists():
    load_dotenv(env_path)

db_url = os.environ.get("DATABASE_URL")
if not db_url:
    print("DATABASE_URL not found")
    sys.exit(1)

def check_db():
    conn = psycopg2.connect(db_url)
    with conn.cursor() as cur:
        # Check users and their roles
        cur.execute("""
            SELECT u.email, r.name, u.id
            FROM users u
            JOIN roles r ON u.role_id = r.id
            ORDER BY u.email
        """)
        users = cur.fetchall()
        print("Users in DB:")
        for email, role, user_id in users:
            print(f" - {email} ({role}) [ID: {user_id}]")
            
        print("\nCases in DB:")
        cur.execute("SELECT id, case_number, created_by FROM cases")
        cases = cur.fetchall()
        for case_id, case_num, creator_id in cases:
            print(f" - Case {case_num} [ID: {case_id}] created by {creator_id}")
            
        print("\nCase Memberships:")
        cur.execute("SELECT case_id, user_id, role_name FROM case_members")
        members = cur.fetchall()
        if not members:
            print(" - None found")
        for cid, uid, rname in members:
            print(f" - User {uid} is {rname} on Case {cid}")

    conn.close()

if __name__ == "__main__":
    check_db()
