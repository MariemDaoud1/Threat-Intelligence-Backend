from fastapi import FastAPI
from app.config import settings
from app.api.v1.iocs import router as iocs_router

app = FastAPI(
    title="Collaborative Threat Intelligence Platform",
    description="Backend & AI Integration for IOC sharing, enrichment, ML scoring and blockchain",
    version="0.1.0",
    docs_url="/docs",
)

@app.get("/")
async def health_check():
    return {
        "status": "ok",
        "service": "threat-intel-backend",
        "version": "0.1.0"
    }

app.include_router(iocs_router, prefix="/api/v1", tags=["IOCs"])