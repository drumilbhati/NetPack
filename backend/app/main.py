from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api import cases, uploads, search

app = FastAPI(
    title="NetPack API",
    description="Backend API for NetPack Network Analysis Tool",
    version="0.1.0",
)

# Configure CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # For development; refine for production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include routers
app.include_router(cases.router, prefix="/cases", tags=["cases"])
app.include_router(uploads.router, prefix="/upload", tags=["uploads"])
app.include_router(search.router, prefix="/search", tags=["search"])


@app.get("/")
async def root():
    return {"message": "Welcome to NetPack API"}


if __name__ == "__main__":
    import os

    import uvicorn

    host = os.getenv("HOST", "127.0.0.1")
    port = int(os.getenv("PORT", "8000"))

    uvicorn.run(app, host=host, port=port)
