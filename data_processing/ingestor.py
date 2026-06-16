#!/usr/bin/env python3
"""Ingest raw PCAP files, hash them, store in MinIO, and link to PostgreSQL."""

import hashlib
import os
import sys
import uuid
from pathlib import Path
from typing import Optional

import boto3
import psycopg2
from botocore.client import Config
from dpi_engine import extract_packet_metadata
from index_metadata import index_records
from psycopg2.extras import Json


def calculate_sha256(file_path: Path) -> str:
    """Calculate SHA256 hash of a file."""
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()


class EvidenceIngestor:
    def __init__(self):
        self.db_url = os.environ.get("DATABASE_URL")
        self.s3_endpoint = os.environ.get("S3_ENDPOINT")
        self.s3_access_key = os.environ.get("S3_ACCESS_KEY")
        self.s3_secret_key = os.environ.get("S3_SECRET_KEY")
        self.bucket_name = os.environ.get("MINIO_EVIDENCE_BUCKET")
        self.es_url = os.environ.get("ELASTICSEARCH_URL", "http://127.0.0.1:9200")
        self.es_index = os.environ.get("ELASTICSEARCH_INDEX", "netpack-flows")

        missing = [
            var
            for var, val in {
                "DATABASE_URL": self.db_url,
                "S3_ENDPOINT": self.s3_endpoint,
                "S3_ACCESS_KEY": self.s3_access_key,
                "S3_SECRET_KEY": self.s3_secret_key,
                "MINIO_EVIDENCE_BUCKET": self.bucket_name,
            }.items()
            if not val
        ]
        if missing:
            raise RuntimeError(
                f"Missing required environment variables: {', '.join(missing)}"
            )

        self.s3_client = boto3.client(
            "s3",
            endpoint_url=self.s3_endpoint,
            aws_access_key_id=self.s3_access_key,
            aws_secret_access_key=self.s3_secret_key,
            config=Config(signature_version="s3v4"),
            region_name="us-east-1",
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
        evidence_id = str(uuid.uuid4())
        object_key = f"cases/{case_id}/{evidence_id}"

        # 2. Connect to DB
        conn = psycopg2.connect(self.db_url)
        try:
            with conn.cursor() as cur:
                # Atomic registration: insert or fetch existing
                cur.execute(
                    """
                    INSERT INTO evidence_files (id, case_id, original_filename, object_key, sha256, byte_size, uploaded_by, status)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, 'uploading')
                    ON CONFLICT (case_id, sha256) DO NOTHING
                    RETURNING id
                    """,
                    (
                        evidence_id,
                        case_id,
                        filename,
                        object_key,
                        sha256,
                        byte_size,
                        uploaded_by,
                    ),
                )
                result = cur.fetchone()
                if result:
                    evidence_id = result[0]
                else:
                    # Duplicate found, retrieve existing evidence_id
                    cur.execute(
                        "SELECT id FROM evidence_files WHERE case_id = %s AND sha256 = %s",
                        (case_id, sha256),
                    )
                    existing_result = cur.fetchone()
                    if not existing_result:
                        raise RuntimeError(
                            f"Race condition: Evidence {sha256} deleted before retrieval."
                        )
                    evidence_id = existing_result[0]
                    print(
                        f"Evidence already exists in case {case_id} with hash {sha256}"
                    )
                    return evidence_id

                # 3. Upload to MinIO
                uploaded_to_s3 = False
                try:
                    self.s3_client.upload_file(
                        str(file_path), self.bucket_name, object_key
                    )
                    uploaded_to_s3 = True

                    # 4. Update status and record forensic events
                    cur.execute(
                        "UPDATE evidence_files SET status = 'registered' WHERE id = %s",
                        (evidence_id,),
                    )

                    cur.execute(
                        """
                        INSERT INTO custody_events (case_id, evidence_id, actor_id, action, details)
                        VALUES (%s, %s, %s, 'ingested', %s)
                        """,
                        (
                            case_id,
                            evidence_id,
                            uploaded_by,
                            Json({"filename": filename, "sha256": sha256}),
                        ),
                    )

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
                            Json({"sha256": sha256}),
                        ),
                    )

                    conn.commit()
                    print(f"Successfully ingested {filename} as {evidence_id}")

                    # 5. DPI and Indexing
                    try:
                        print(f"Running DPI for {filename}...")
                        raw_records = extract_packet_metadata(file_path)

                        # Use the same normalization logic as index_metadata.py
                        from index_metadata import normalize_record

                        context = {
                            "case_id": case_id,
                            "evidence_id": evidence_id,
                            "sha256": sha256,
                        }
                        records = [
                            normalize_record(rec, context) for rec in raw_records
                        ]

                        if records:
                            print(
                                f"Indexing {len(records)} packets into Elasticsearch..."
                            )
                            index_records(records, self.es_url, self.es_index)
                            print(f"Successfully indexed metadata for {filename}")
                        else:
                            print(f"No packets found in {filename} to index.")
                    except Exception as e:
                        print(
                            f"DPI/Indexing failed for {filename}: {e}", file=sys.stderr
                        )

                    return evidence_id

                except Exception as upload_exc:
                    if uploaded_to_s3:
                        try:
                            self.s3_client.delete_object(
                                Bucket=self.bucket_name, Key=object_key
                            )
                        except Exception as delete_exc:
                            print(
                                f"Failed to cleanup orphaned object {object_key}: {delete_exc}",
                                file=sys.stderr,
                            )
                    raise upload_exc

        except Exception as e:
            conn.rollback()
            raise e
        finally:
            conn.close()


if __name__ == "__main__":
    import argparse

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
