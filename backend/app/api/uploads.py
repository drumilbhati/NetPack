import hashlib
import json
import logging
import uuid
from pathlib import Path

from fastapi import APIRouter, Depends, File, HTTPException, UploadFile, BackgroundTasks
from fastapi.concurrency import run_in_threadpool

from app.core.database import get_db_conn
from app.dependencies.auth import require_case_access, require_role
from app.schemas.auth import UserContext

router = APIRouter()
logger = logging.getLogger(__name__)


def run_background_analysis(
    case_id: str,
    evidence_id: str,
    file_path: str,
    filename: str,
    sha256: str,
    uploaded_by: str
):
    import sys
    from unittest.mock import MagicMock

    # Mock confluent_kafka if not present
    if "confluent_kafka" not in sys.modules:
        sys.modules["confluent_kafka"] = MagicMock()

    # Add project root to sys.path
    project_root = str(Path(__file__).resolve().parents[3])
    if project_root not in sys.path:
        sys.path.append(project_root)

    try:
        from data_processing.worker import ParserWorker
        worker = ParserWorker()
        job = {
            "case_id": case_id,
            "evidence_id": evidence_id,
            "object_key": file_path,
            "filename": filename,
            "sha256": sha256,
            "uploaded_by": uploaded_by
        }
        worker.process_job(job)
        logger.info(f"Background analysis completed successfully for {filename}")
    except Exception as e:
        logger.error(f"Background analysis failed for {filename}: {e}", exc_info=True)


# Define and resolve the upload directory
UPLOAD_DIR = Path("uploads").resolve()
if not UPLOAD_DIR.exists():
    UPLOAD_DIR.mkdir(parents=True, exist_ok=True)

# Magic numbers for PCAP and PCAPNG file formats
PCAP_MAGIC_NUMBERS = {
    b"\xa1\xb2\xc3\xd4",  # Big-endian PCAP
    b"\xd4\xc3\xb2\xa1",  # Little-endian PCAP
    b"\xa1\xb2\x3c\x4d",  # Big-endian Nanosecond PCAP
    b"\x4d\x3c\xb2\xa1",  # Little-endian Nanosecond PCAP
    b"\x0a\x0d\x0d\x0a",  # PCAPNG Section Header Block
}

# Maximum upload size: 100 MB
MAX_UPLOAD_SIZE = 100 * 1024 * 1024


class SizeLimitExceeded(Exception):
    """Exception raised when the uploaded file exceeds the allowed size."""


def save_file_sync(source_file, target_path: Path):
    """Synchronous helper function to write the file stream with size tracking and hash calculation."""
    bytes_written = 0
    chunk_size = 1024 * 1024  # 1MB chunks
    hasher = hashlib.sha256()
    with open(target_path, "wb") as buffer:
        while True:
            chunk = source_file.read(chunk_size)
            if not chunk:
                break
            bytes_written += len(chunk)
            if bytes_written > MAX_UPLOAD_SIZE:
                raise SizeLimitExceeded()
            buffer.write(chunk)
            hasher.update(chunk)
    return bytes_written, hasher.hexdigest()


@router.post("/{case_id}")
async def upload_pcap(
    case_id: str,
    background_tasks: BackgroundTasks,
    file: UploadFile = File(...),
    current_user: UserContext = Depends(require_role("admin", "investigator")),
):
    conn = None
    file_path = None
    try:
        conn = get_db_conn()
        require_case_access(conn, current_user, case_id, write=True)

        # 1. Filename Guard and Case-Insensitive Extension Check
        if not file.filename:
            raise HTTPException(
                status_code=400, detail="Invalid request. Filename is missing."
            )

        sanitized_name = Path(file.filename).name
        filename_lower = sanitized_name.lower()
        if not filename_lower.endswith((".pcap", ".pcapng")):
            raise HTTPException(
                status_code=400,
                detail="Invalid file type. Only PCAP files are allowed.",
            )

        # 2. Content Signature (Magic Number) Validation
        try:
            header = await file.read(4)
            await file.seek(
                0
            )  # Rewind pointer back to start so chunk copying starts from the beginning
        except Exception:
            raise HTTPException(
                status_code=400, detail="Failed to read file header for validation."
            )

        if len(header) < 4 or header not in PCAP_MAGIC_NUMBERS:
            raise HTTPException(
                status_code=400,
                detail="Invalid file content. File does not match PCAP/PCAPNG format signature.",
            )

        # 3. Path Traversal & Name Collision Protections
        unique_filename = f"{uuid.uuid4()}_{sanitized_name}"
        file_path = (UPLOAD_DIR / unique_filename).resolve()

        # Verify that the resolved absolute path is strictly a descendant of UPLOAD_DIR
        if UPLOAD_DIR not in file_path.parents:
            raise HTTPException(
                status_code=400, detail="Path traversal attempt detected."
            )

        # 4. Offload Blocking File Write and Hashing to Thread Pool
        try:
            size, sha256 = await run_in_threadpool(save_file_sync, file.file, file_path)
        except SizeLimitExceeded:
            if file_path and file_path.exists():
                try:
                    file_path.unlink()
                except Exception:
                    logger.exception(f"Failed to cleanup file {file_path}")
            raise HTTPException(
                status_code=413,
                detail="File size exceeds the maximum limit of 100 MB.",
            ) from None
        except Exception as e:
            if file_path and file_path.exists():
                try:
                    file_path.unlink()
                except Exception:
                    logger.exception(f"Failed to cleanup file {file_path}")
            raise HTTPException(
                status_code=500,
                detail="An error occurred while saving the uploaded file on the server.",
            ) from e

        # 5. Database Persistence
        try:
            with conn.cursor() as cur:
                # Check for duplicate SHA256 in the same case
                cur.execute(
                    "SELECT id FROM evidence_files WHERE case_id = %s AND sha256 = %s",
                    (case_id, sha256),
                )
                if cur.fetchone():
                    if file_path and file_path.exists():
                        file_path.unlink()
                    raise HTTPException(
                        status_code=409,
                        detail="A file with this content has already been uploaded to this case.",
                    )

                cur.execute(
                    """
                    INSERT INTO evidence_files (case_id, original_filename, object_key, sha256, byte_size, status, uploaded_by)
                    VALUES (%s, %s, %s, %s, %s, 'registered', %s)
                    RETURNING id
                    """,
                    (
                        case_id,
                        sanitized_name,
                        str(file_path),
                        sha256,
                        size,
                        current_user.id,
                    ),
                )
                evidence_id = cur.fetchone()["id"]

                # Log custody event
                cur.execute(
                    """
                    INSERT INTO custody_events (case_id, evidence_id, actor_id, action, details)
                    VALUES (%s, %s, %s, 'upload', %s)
                    """,
                    (
                        case_id,
                        evidence_id,
                        current_user.id,
                        json.dumps({"filename": sanitized_name}),
                    ),
                )

                from app.core.audit import log_audit_event
                log_audit_event(
                    conn,
                    current_user,
                    action="upload",
                    target_type="evidence",
                    target_id=str(evidence_id),
                    case_id=case_id,
                    evidence_id=str(evidence_id),
                    metadata={"filename": sanitized_name, "size": size}
                )

                conn.commit()
                
            # 6. Offload DPI and Analysis
            try:
                import sys
                project_root = str(Path(__file__).resolve().parents[3])
                if project_root not in sys.path:
                    sys.path.append(project_root)
                from data_processing.kafka_utils import get_kafka_producer, produce_message
                
                producer = get_kafka_producer()
                job_payload = {
                    "type": "pcap_analysis",
                    "case_id": case_id,
                    "evidence_id": str(evidence_id),
                    "object_key": str(file_path),
                    "filename": sanitized_name,
                    "sha256": sha256,
                    "uploaded_by": current_user.id
                }
                
                logger.info(f"Queuing parser job for {sanitized_name}...")
                produce_message(producer, "parser-jobs", str(evidence_id), job_payload)
            except Exception as kafka_exc:
                logger.warning(f"Failed to queue Kafka job: {kafka_exc}")

            # Queue local synchronous fallback analysis
            background_tasks.add_task(
                run_background_analysis,
                case_id,
                str(evidence_id),
                str(file_path),
                sanitized_name,
                sha256,
                current_user.id
            )

            return {
                "id": str(evidence_id),
                "filename": sanitized_name,
                "status": "registered",
                "sha256": sha256,
                "size": size,
            }
        except HTTPException:
            raise
        except Exception as e:
            logger.exception("Upload failed with unexpected exception")
            if conn is not None:
                conn.rollback()
            if file_path and file_path.exists():
                file_path.unlink()
            raise HTTPException(
                status_code=500, detail=f"Database error: {str(e)}"
            ) from e

    finally:
        if conn is not None:
            conn.close()
