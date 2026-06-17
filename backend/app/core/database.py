import os

import psycopg2
from psycopg2.extras import RealDictCursor


def get_db_conn():
    db_url = os.getenv("DATABASE_URL")
    if not db_url:
        raise RuntimeError("DATABASE_URL is not configured")
    # If running inside docker, localhost might need to be postgres
    if "localhost" in db_url and os.getenv("DOCKER_ENV"):
        db_url = db_url.replace("localhost", "postgres")
    return psycopg2.connect(db_url, cursor_factory=RealDictCursor)
