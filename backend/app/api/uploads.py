import uuid
from pathlib import Path

from fastapi import APIRouter, File, HTTPException, UploadFile
from fastapi.concurrency import run_in_threadpool

router = APIRouter()

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
    """Synchronous helper function to write the file stream with size tracking."""
    bytes_written = 0
    chunk_size = 1024 * 1024  # 1MB chunks
    with open(target_path, "wb") as buffer:
        while True:
            chunk = source_file.read(chunk_size)
            if not chunk:
                break
            bytes_written += len(chunk)
            if bytes_written > MAX_UPLOAD_SIZE:
                raise SizeLimitExceeded()
            buffer.write(chunk)


@router.post("/")
async def upload_pcap(file: UploadFile = File(...)):
    # 1. Filename Guard and Case-Insensitive Extension Check
    if not file.filename:
        raise HTTPException(
            status_code=400, detail="Invalid request. Filename is missing."
        )

    filename_lower = file.filename.lower()
    if not filename_lower.endswith((".pcap", ".pcapng")):
        raise HTTPException(
            status_code=400, detail="Invalid file type. Only PCAP files are allowed."
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
    sanitized_name = Path(file.filename).name
    unique_filename = f"{uuid.uuid4()}_{sanitized_name}"
    file_path = (UPLOAD_DIR / unique_filename).resolve()

    # Verify that the resolved absolute path is strictly a descendant of UPLOAD_DIR
    if UPLOAD_DIR not in file_path.parents:
        raise HTTPException(status_code=400, detail="Path traversal attempt detected.")

    # 4. Offload Blocking File Write to Thread Pool
    try:
        await run_in_threadpool(save_file_sync, file.file, file_path)
    except SizeLimitExceeded:
        if file_path.exists():
            try:
                file_path.unlink()
            except Exception:
                pass
        raise HTTPException(
            status_code=413,
            detail="File size exceeds the maximum limit of 100 MB.",
        ) from None
    except Exception as e:
        if file_path.exists():
            try:
                file_path.unlink()
            except Exception:
                pass
        raise HTTPException(
            status_code=500,
            detail="An error occurred while saving the uploaded file on the server.",
        ) from e

    # Return relative path component to preserve security and internal server structures
    return {
        "filename": file.filename,
        "status": "uploaded",
        "path": f"uploads/{unique_filename}",
    }
