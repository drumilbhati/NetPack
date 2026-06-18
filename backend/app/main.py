from pathlib import Path
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from dotenv import load_dotenv

# Load environment variables from infra/.env
env_path = Path(__file__).resolve().parents[2] / "infra" / ".env"
load_dotenv(dotenv_path=env_path)

from app.api import (
    alerts,
    auth,
    cases,
    graph,
    reports,
    search,
    stats,
    timeline,
    uploads,
)

app = FastAPI(
    title="NetPack API",
    description="Backend API for NetPack Network Analysis Tool",
    version="0.1.0",
)

# Configure CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # For development; refine for production
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include routers with /api prefix
app.include_router(auth.router, prefix="/api/auth", tags=["auth"])
app.include_router(cases.router, prefix="/api/cases", tags=["cases"])
app.include_router(alerts.router, prefix="/api/alerts", tags=["alerts"])
app.include_router(stats.router, prefix="/api/stats", tags=["stats"])
app.include_router(uploads.router, prefix="/api/upload", tags=["uploads"])
app.include_router(search.router, prefix="/api/search", tags=["search"])
app.include_router(graph.router, prefix="/api/graph", tags=["graph"])
app.include_router(timeline.router, prefix="/api/timeline", tags=["timeline"])
app.include_router(reports.router, prefix="/api/reports", tags=["reports"])


@app.get("/")
async def root():
    return {"message": "Welcome to NetPack API"}


if __name__ == "__main__":
    import os

    import uvicorn

    host = os.getenv("HOST", "127.0.0.1")
    port = int(os.getenv("PORT", "8000"))

    # Force reload of data_processing modules (v2)
    uvicorn.run(app, host=host, port=port)
