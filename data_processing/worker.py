import json
import os
import sys
import tempfile
import traceback
from pathlib import Path

import boto3
import pandas as pd
import psycopg2
from botocore.client import Config

from .dpi_engine import (
    extract_flow_metadata,
    extract_packet_metadata,
    process_pcap_iterator,
)
from .index_metadata import index_records, normalize_record
from .kafka_utils import get_kafka_consumer
from .threat_detection_service import ThreatDetectionService

# Anomaly Detection Integration
MODEL_PATH = os.path.join(
    os.path.dirname(__file__),
    "..",
    "ml_models",
    "saved_models",
    "anomaly_detector.joblib",
)

try:
    from ml_models.anomaly_detector import AnomalyDetector

    ANOMALY_DETECTOR = AnomalyDetector()
    if os.path.exists(MODEL_PATH):
        ANOMALY_DETECTOR.load(MODEL_PATH)
        ML_READY = True
    else:
        ML_READY = False
except ImportError:
    ML_READY = False


class ParserWorker:
    def __init__(self):
        self.db_url = os.environ.get("DATABASE_URL")
        self.s3_endpoint = os.environ.get("S3_ENDPOINT")
        self.s3_access_key = os.environ.get("S3_ACCESS_KEY")
        self.s3_secret_key = os.environ.get("S3_SECRET_KEY")
        self.bucket_name = os.environ.get("MINIO_EVIDENCE_BUCKET", "evidence")
        self.es_url = os.environ.get("ELASTICSEARCH_URL", "http://localhost:9200")
        self.es_index = os.environ.get("ELASTICSEARCH_INDEX", "netpack-flows")

        self.s3_client = boto3.client(
            "s3",
            endpoint_url=self.s3_endpoint,
            aws_access_key_id=self.s3_access_key,
            aws_secret_access_key=self.s3_secret_key,
            config=Config(signature_version="s3v4"),
            region_name="us-east-1",
        )
        self.threat_service = ThreatDetectionService(
            db_url=self.db_url, model_path=MODEL_PATH
        )

    def verify_rbac(self, user_id: str, case_id: str) -> bool:
        """
        Verifies that the user has access to the case.
        """
        if not user_id:
            return True  # System actions might not have user_id

        try:
            conn = psycopg2.connect(self.db_url)
            with conn.cursor() as cur:
                # Check if user is admin or a member of the case
                cur.execute(
                    """
                    SELECT 1 FROM users u
                    JOIN roles r ON u.role_id = r.id
                    LEFT JOIN case_members cm ON cm.user_id = u.id AND cm.case_id = %s
                    LEFT JOIN cases c ON c.id = %s
                    WHERE u.id = %s AND (r.name = 'admin' OR cm.user_id IS NOT NULL OR c.created_by = %s)
                    LIMIT 1
                    """,
                    (case_id, case_id, user_id, user_id),
                )
                return cur.fetchone() is not None
        except Exception as e:
            print(f"RBAC check failed: {e}")
            return False
        finally:
            conn.close()

    def process_job(self, job: dict):
        case_id = job.get("case_id")
        evidence_id = job.get("evidence_id")
        object_key = job.get("object_key")
        filename = job.get("filename")
        sha256 = job.get("sha256")
        uploaded_by = job.get("uploaded_by")

        print(f"[*] Processing evidence {evidence_id} for case {case_id}")

        # 1. RBAC Verification
        if not self.verify_rbac(uploaded_by, case_id):
            print(f"[!] RBAC Violation: User {uploaded_by} does not have access to case {case_id}")
            return

        # Update status of evidence in DB to 'parsing' and insert custody log
        try:
            conn = psycopg2.connect(self.db_url)
            with conn.cursor() as cur:
                cur.execute(
                    "UPDATE evidence_files SET status = 'parsing' WHERE id = %s",
                    (evidence_id,)
                )
                cur.execute(
                    """
                    INSERT INTO custody_events (case_id, evidence_id, actor_id, action, details)
                    VALUES (%s, %s, %s, 'parsing_started', %s)
                    """,
                    (
                        case_id,
                        evidence_id,
                        uploaded_by,
                        json.dumps({"filename": filename, "status": "parsing", "worker": "ParserWorker"}),
                    ),
                )
                conn.commit()
            conn.close()
        except Exception as db_err:
            print(f"[!] Warning: Failed to update status to parsing: {db_err}")

        # 2. Check local disk or download from MinIO
        is_local_file = False
        tmp_path = ""
        try:
            if os.path.exists(object_key):
                tmp_path = object_key
                is_local_file = True
                print(f"[*] Found local file at {object_key}, skipping MinIO download.")
            else:
                with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as tmp:
                    tmp_path = tmp.name
                
                try:
                    self.s3_client.download_file(self.bucket_name, object_key, tmp_path)
                except Exception as e:
                    if os.path.exists(tmp_path):
                        os.unlink(tmp_path)
                    raise e
            
            # 3. DPI and Analysis
            print(f"[*] Running DPI for {filename}...")
            
            # Use iterator to process packets
            p_records = []
            for rec in extract_packet_metadata(process_pcap_iterator(tmp_path)):
                p_records.append(normalize_record(rec, {"case_id": case_id, "evidence_id": evidence_id, "sha256": sha256}))

            # Use iterator to process flows
            f_records = []
            raw_flows = extract_flow_metadata(process_pcap_iterator(tmp_path))
            
            if ML_READY and raw_flows:
                df = pd.DataFrame(raw_flows)
                scores = ANOMALY_DETECTOR.score(df)
                preds = ANOMALY_DETECTOR.predict(df)
                for i, rec in enumerate(raw_flows):
                    rec["anomaly_score"] = float(scores[i])
                    rec["is_anomaly"] = bool(preds[i] == -1)

            for rec in raw_flows:
                f_records.append(normalize_record(rec, {"case_id": case_id, "evidence_id": evidence_id, "sha256": sha256}))

            all_records = p_records + f_records

            if all_records:
                print(f"[*] Indexing {len(all_records)} records...")
                index_records(all_records, self.es_url, self.es_index)
                
                print(f"[*] Running Threat Detection...")
                try:
                    conn = psycopg2.connect(self.db_url)
                    with conn.cursor() as cur:
                        cur.execute(
                            """
                            INSERT INTO custody_events (case_id, evidence_id, actor_id, action, details)
                            VALUES (%s, %s, %s, 'analysis_started', %s)
                            """,
                            (
                                case_id,
                                evidence_id,
                                uploaded_by,
                                json.dumps({"filename": filename, "status": "analyzing", "analysis_type": "threat_and_anomaly_detection"}),
                            ),
                        )
                        conn.commit()
                    conn.close()
                except Exception as db_err:
                    print(f"[!] Warning: Failed to insert analysis_started custody event: {db_err}")

                self.threat_service.process_evidence(case_id, evidence_id, p_records, f_records)
                
                # Update status in DB to 'parsed' and log custody event for completion
                conn = psycopg2.connect(self.db_url)
                with conn.cursor() as cur:
                    cur.execute(
                        "UPDATE evidence_files SET status = 'parsed', parsed_at = NOW() WHERE id = %s",
                        (evidence_id,)
                    )
                    cur.execute(
                        """
                        INSERT INTO custody_events (case_id, evidence_id, actor_id, action, details)
                        VALUES (%s, %s, %s, 'analysis_completed', %s)
                        """,
                        (
                            case_id,
                            evidence_id,
                            uploaded_by,
                            json.dumps({"filename": filename, "status": "parsed", "result": "success"}),
                        ),
                    )
                    conn.commit()
                conn.close()
                print(f"[+] Successfully processed {evidence_id}")
            else:
                print(f"[!] No records extracted from {filename}")
                conn = psycopg2.connect(self.db_url)
                with conn.cursor() as cur:
                    cur.execute(
                        "UPDATE evidence_files SET status = 'failed', failure_reason = 'No packet records extracted' WHERE id = %s",
                        (evidence_id,)
                    )
                    cur.execute(
                        """
                        INSERT INTO custody_events (case_id, evidence_id, actor_id, action, details)
                        VALUES (%s, %s, %s, 'analysis_failed', %s)
                        """,
                        (
                            case_id,
                            evidence_id,
                            uploaded_by,
                            json.dumps({"filename": filename, "status": "failed", "error": "No records extracted"}),
                        ),
                    )
                    conn.commit()
                conn.close()

        except Exception as e:
            print(f"[!] Error processing {evidence_id}: {e}")
            traceback.print_exc()
            # Update status to failed and log custody event
            try:
                conn = psycopg2.connect(self.db_url)
                with conn.cursor() as cur:
                    cur.execute(
                        "UPDATE evidence_files SET status = 'failed', failure_reason = %s WHERE id = %s",
                        (str(e), evidence_id)
                    )
                    cur.execute(
                        """
                        INSERT INTO custody_events (case_id, evidence_id, actor_id, action, details)
                        VALUES (%s, %s, %s, 'analysis_failed', %s)
                        """,
                        (
                            case_id,
                            evidence_id,
                            uploaded_by,
                            json.dumps({"filename": filename, "status": "failed", "error": str(e)}),
                        ),
                    )
                    conn.commit()
                conn.close()
            except Exception as db_err:
                print(f"[!] Warning: Failed to update status to failed: {db_err}")
        finally:
            if not is_local_file and tmp_path and os.path.exists(tmp_path):
                os.unlink(tmp_path)

    def process_streaming_chunk(self, chunk: dict):
        """
        Process a chunk of packets from the live stream.
        """
        case_id = chunk.get("case_id")
        user_id = chunk.get("user_id")
        packets_data = chunk.get("packets", [])

        if not packets_data:
            return

        print(f"[*] Processing streaming chunk of {len(packets_data)} packets for case {case_id}")

        # 1. RBAC Verification
        if not self.verify_rbac(user_id, case_id):
            print(f"[!] RBAC Violation: User {user_id} does not have access to case {case_id}")
            return

        # 2. Decode packets
        from base64 import b64decode
        from scapy.all import Ether, IP

        scapy_packets = []
        for pdata in packets_data:
            try:
                raw_pkt = b64decode(pdata["data"])
                # We don't know the exact layer, Ether is a safe bet for most captures, 
                # but Scapy can often auto-detect if we use the right constructor.
                # For now, let's assume raw IP if it looks like it, or Ether.
                pkt = Ether(raw_pkt)
                if not pkt.haslayer(IP):
                    pkt = IP(raw_pkt)
                
                # Manually set the time since it was lost in serialization
                pkt.time = pdata["timestamp"]
                scapy_packets.append(pkt)
            except Exception as e:
                print(f"[-] Failed to decode packet: {e}")

        if not scapy_packets:
            return

        # 3. DPI and Analysis
        p_records = []
        for rec in extract_packet_metadata(scapy_packets):
            p_records.append(normalize_record(rec, {"case_id": case_id, "evidence_id": "live-stream"}))

        f_records = []
        raw_flows = extract_flow_metadata(scapy_packets)
        
        if ML_READY and raw_flows:
            df = pd.DataFrame(raw_flows)
            scores = ANOMALY_DETECTOR.score(df)
            preds = ANOMALY_DETECTOR.predict(df)
            for i, rec in enumerate(raw_flows):
                rec["anomaly_score"] = float(scores[i])
                rec["is_anomaly"] = bool(preds[i] == -1)

        for rec in raw_flows:
            f_records.append(normalize_record(rec, {"case_id": case_id, "evidence_id": "live-stream"}))

        all_records = p_records + f_records

        if all_records:
            index_records(all_records, self.es_url, self.es_index)
            self.threat_service.process_evidence(case_id, "live-stream", p_records, f_records)

    def run(self):
        consumer = get_kafka_consumer("netpack-parser-group")
        consumer.subscribe(["parser-jobs", "raw-capture-chunks"])
        
        print("[*] Worker started, listening on 'parser-jobs' and 'raw-capture-chunks'...")
        try:
            while True:
                msg = consumer.poll(1.0)
                if msg is None:
                    continue
                if msg.error():
                    print(f"Consumer error: {msg.error()}")
                    continue

                try:
                    topic = msg.topic()
                    data = json.loads(msg.value().decode("utf-8"))
                    
                    if topic == "parser-jobs":
                        self.process_job(data)
                    elif topic == "raw-capture-chunks":
                        self.process_streaming_chunk(data)
                        
                except Exception as e:
                    print(f"Error decoding/processing message: {e}")
                    traceback.print_exc()
        except KeyboardInterrupt:
            print("[*] Worker stopped by user.")


if __name__ == "__main__":
    # Load .env if exists for local testing
    try:
        from dotenv import load_dotenv
        env_path = Path(__file__).parent.parent / "infra" / ".env"
        if env_path.exists():
            load_dotenv(env_path)
    except ImportError:
        pass

    worker = ParserWorker()
    worker.run()
