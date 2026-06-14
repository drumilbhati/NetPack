from fastapi import FastAPI

from app.api import cases, uploads

app = FastAPI(
    title="NetPack API",
    description="Backend API for NetPack Network Analysis Tool",
    version="0.1.0",
)

# Include routers
app.include_router(cases.router, prefix="/cases", tags=["cases"])
app.include_router(uploads.router, prefix="/upload", tags=["uploads"])


@app.get("/")
async def root():
    return {"message": "Welcome to NetPack API"}


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000)
