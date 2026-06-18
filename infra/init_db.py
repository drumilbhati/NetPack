import os
import sys
import psycopg2
from pathlib import Path
from dotenv import load_dotenv

# Try to load environment variables from local .env or infra/.env
infra_dir = Path(__file__).resolve().parent
root_dir = infra_dir.parent

load_dotenv(infra_dir / ".env")
load_dotenv(root_dir / "backend" / ".env")

def init_database():
    db_url = os.getenv("DATABASE_URL")
    if not db_url:
        print("Error: DATABASE_URL environment variable is not set.", file=sys.stderr)
        print("Please set it in your environment or in infra/.env or backend/.env file.", file=sys.stderr)
        sys.exit(1)

    print(f"Connecting to database to initialize schema: {db_url.split('@')[-1]}")
    
    try:
        conn = psycopg2.connect(db_url)
        conn.autocommit = True
        cur = conn.cursor()
    except Exception as e:
        print(f"Failed to connect to database: {e}", file=sys.stderr)
        sys.exit(1)

    # 1. Run Schema Init Files
    init_files = [
        "postgres/init/001_schema.sql",
        "postgres/init/002_add_uploading_status.sql",
        "postgres/init/003_auth.sql"
    ]

    for sql_file in init_files:
        file_path = infra_dir / sql_file
        if not file_path.exists():
            print(f"Warning: SQL init file not found at {file_path}", file=sys.stderr)
            continue
            
        print(f"Applying SQL file: {sql_file}...")
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                sql_content = f.read()
            cur.execute(sql_content)
            print(f"Successfully applied {sql_file}")
        except Exception as e:
            print(f"Error applying {sql_file}: {e}", file=sys.stderr)

    # 2. Apply Additional Performance Indexes
    indexes = [
        "CREATE INDEX IF NOT EXISTS idx_cases_created_at_desc ON cases (created_at DESC);",
        "CREATE INDEX IF NOT EXISTS idx_cases_created_by ON cases (created_by);",
        "CREATE INDEX IF NOT EXISTS idx_case_members_user_id ON case_members (user_id);"
    ]

    print("Applying performance indexes...")
    for idx_sql in indexes:
        try:
            cur.execute(idx_sql)
            print(f"Applied index query: {idx_sql.strip()}")
        except Exception as e:
            print(f"Error applying index query: {e}", file=sys.stderr)

    cur.close()
    conn.close()
    print("Database initialization completed successfully!")

if __name__ == "__main__":
    init_database()
