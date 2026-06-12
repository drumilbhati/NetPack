#!/usr/bin/env python3
"""Ingest raw PCAP files, hash them, store in MinIO, and link to PostgreSQL."""

import hashlib
import os
import sys
from pathlib import Path
from typing import Optional

import boto3
import psycopg2
from botocore.client import Config


def calculate_sha256(file_path: Path) -> str:
    """Calculate SHA256 hash of a file."""
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()


class EvidenceIngestor:
    def __init__(self):
        self.db_url = os.getenv(
            "DATABASE_URL",
            "postgresql://netpack:netpack_dev_password@127.0.0.1:5432/netpack",
        )
        self.s3_endpoint = os.getenv("S3_ENDPOINT", "http://127.0.0.1:9000")
        self.s3_access_key = os.getenv("S3_ACCESS_KEY", "netpack")
        self.s3_secret_key = os.getenv("S3_SECRET_KEY", "netpack_dev_password")
        self.bucket_name = os.getenv("MINIO_EVIDENCE_BUCKET", "evidence")

        self.s3_client = boto3.client(
            "s3",
            endpoint_url=self.s3_endpoint,
            aws_access_key_id=self.s3_access_key,
            aws_secret_access_key=self.s3_secret_key,
            config=Config(signature_version="s3v4"),
            region_name="us-east-1",  # MinIO requires a region, though it can be anything
        )

    def ingest(
        self, case_id: str, file_path: Path, uploaded_by: Optional[str] = None
    ) -> str:
        """
        Ingest a PCAP file: hash, upload to MinIO, and register in DB.
        Returns the evidence_id.
        """
        if not file_path.exists():
            raise FileNotFoundError(f"File not found: {file_path}")

        # 1. Calculate metadata
        sha256 = calculate_sha256(file_path)
        byte_size = file_path.stat().st_size
        filename = file_path.name

        # 2. Connect to DB
        conn = psycopg2.connect(self.db_url)
        try:
            with conn.cursor() as cur:
                # Check for duplicate in this case
                cur.execute(
                    "SELECT id FROM evidence_files WHERE case_id = %s AND sha256 = %s",
                    (case_id, sha256),
                )
                existing = cur.fetchone()
                if existing:
                    print(
                        f"Evidence already exists in case {case_id} with hash {sha256}"
                    )
                    return existing[0]

                # Insert evidence record to get evidence_id
                # Note: object_key is temporary until we have the ID
                cur.execute(
                    """
                    INSERT INTO evidence_files (case_id, original_filename, object_key, sha256, byte_size, uploaded_by)
                    VALUES (%s, %s, %s, %s, %s, %s)
                    RETURNING id
                    """,
                    (case_id, filename, "PENDING", sha256, byte_size, uploaded_by),
                )
                evidence_id = cur.fetchone()[0]

                # 3. Upload to MinIO
                object_key = f"cases/{case_id}/{evidence_id}/{filename}"
                self.s3_client.upload_file(str(file_path), self.bucket_name, object_key)

                # 4. Update record with final object_key and status
                cur.execute(
                    "UPDATE evidence_files SET object_key = %s, status = 'registered' WHERE id = %s",
                    (object_key, evidence_id),
                )

                # 5. Record first custody event
                cur.execute(
                    """
                    INSERT INTO custody_events (case_id, evidence_id, actor_id, action, details)
                    VALUES (%s, %s, %s, 'ingested', %s)
                    """,
                    (
                        case_id,
                        evidence_id,
                        uploaded_by,
                        psycopg2.extras.Json({"filename": filename, "sha256": sha256}),
                    ),
                )

                # 6. Record audit event
                cur.execute(
                    """
                    INSERT INTO audit_events (actor_id, action, target_type, target_id, case_id, evidence_id, metadata)
                    VALUES (%s, 'UPLOAD', 'evidence_file', %s, %s, %s, %s)
                    """,
                    (
                        uploaded_by,
                        evidence_id,
                        case_id,
                        evidence_id,
                        psycopg2.extras.Json({"sha256": sha256}),
                    ),
                )

                conn.commit()
                print(f"Successfully ingested {filename} as {evidence_id}")
                return evidence_id
        except Exception as e:
            conn.rollback()
            raise e
        finally:
            conn.close()


if __name__ == "__main__":
    import argparse

    import psycopg2.extras  # For Json

    parser = argparse.ArgumentParser(description="Ingest a PCAP file into NetPack.")
    parser.add_argument("case_id", help="Target Case UUID")
    parser.add_argument("file_path", type=Path, help="Path to the PCAP file")
    parser.add_argument("--user-id", help="Optional User UUID performing the upload")

    args = parser.parse_args()

    # Load .env if exists for local testing
    try:
        from dotenv import load_dotenv

        load_dotenv(Path(__file__).parent.parent / "infra" / ".env")
    except ImportError:
        pass

    ingestor = EvidenceIngestor()
    try:
        ingestor.ingest(args.case_id, args.file_path, args.user_id)
    except Exception as exc:
        print(f"Ingestion failed: {exc}", file=sys.stderr)
        sys.exit(1)
