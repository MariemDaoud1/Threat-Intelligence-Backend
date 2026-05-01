from fastapi import FastAPI
from slowapi.errors import RateLimitExceeded
from slowapi.extension import _rate_limit_exceeded_handler
from app.api.v1.iocs import router as iocs_router
from app.api.v1.admin import router as admin_router
from app.api.v1.register import router as register_router
from app.api.v1.contributor_auth import router as contributor_router
from app.api.v1.submissions import router as submissions_router
from app.rate_limiter import limiter
import app.models.register  

app = FastAPI(
    title="Collaborative Threat Intelligence Platform",
    description="Backend & AI Integration for IOC sharing, enrichment, ML scoring and blockchain",
    version="0.1.0",
    docs_url="/docs",
)

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

@app.get("/")
async def health_check():
    return {
        "status": "ok",
        "service": "threat-intel-backend",
        "version": "0.1.0"
    }

app.include_router(iocs_router, prefix="/api/v1", tags=["IOCs"])
app.include_router(submissions_router, prefix="/api/v1", tags=["Submissions"])
app.include_router(admin_router, prefix="/api/v1", tags=["Admin"])
app.include_router(register_router, prefix="/api/v1", tags=["Registration"])
app.include_router(contributor_router, prefix="/api/v1", tags=["Contributors"])