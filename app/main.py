from fastapi import FastAPI
from app.config import settings

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