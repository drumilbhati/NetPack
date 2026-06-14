import shutil
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


def save_file_sync(source_file, target_path: Path):
    """Synchronous helper function to write the file stream."""
    with open(target_path, "wb") as buffer:
        shutil.copyfileobj(source_file, buffer)


@router.post("/")
async def upload_pcap(file: UploadFile = File(...)):
    # 1. Filename Extension Check
    if not file.filename.endswith((".pcap", ".pcapng")):
        raise HTTPException(
            status_code=400, detail="Invalid file type. Only PCAP files are allowed."
        )

    # 2. Content Signature (Magic Number) Validation
    try:
        header = await file.read(4)
        await file.seek(
            0
        )  # Rewind pointer back to start so copyfileobj writes the whole file
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
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to write uploaded file to disk: {str(e)}",
        )

    return {"filename": file.filename, "status": "uploaded", "path": str(file_path)}
