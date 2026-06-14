import os
import shutil

from fastapi import APIRouter, File, HTTPException, UploadFile

router = APIRouter()

# Placeholder for upload directory
UPLOAD_DIR = "uploads"
if not os.path.exists(UPLOAD_DIR):
    os.makedirs(UPLOAD_DIR)


@router.post("/")
async def upload_pcap(file: UploadFile = File(...)):
    if not file.filename.endswith((".pcap", ".pcapng")):
        raise HTTPException(
            status_code=400, detail="Invalid file type. Only PCAP files are allowed."
        )

    file_path = os.path.join(UPLOAD_DIR, file.filename)
    with open(file_path, "wb") as buffer:
        shutil.copyfileobj(file.file, buffer)

    return {"filename": file.filename, "status": "uploaded", "path": file_path}
