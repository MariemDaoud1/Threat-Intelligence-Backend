from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from slowapi.errors import RateLimitExceeded
from slowapi.extension import _rate_limit_exceeded_handler

from app.api.v1.admin import router as admin_router
from app.api.v1.auth import router as auth_router
from app.api.v1.contributor_auth import router as contributor_router
from app.api.v1.dashboard import router as dashboard_router
from app.api.v1.iocs import router as iocs_router
from app.api.v1.register import router as register_router
from app.api.v1.submissions import router as submissions_router
from app.config import settings
from app.rate_limiter import limiter
import app.models.register

app = FastAPI(
    title="Collaborative Threat Intelligence Platform",
    description="Backend API for collaborative threat intelligence sharing",
    version="0.1.0",
    docs_url="/docs",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ALLOW_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)


@app.get("/")
async def health_check():
    return {"status": "ok", "service": "threat-intel-backend", "version": "0.1.0"}


for prefix, include_schema in (("/api/v1", True), ("", False)):
    app.include_router(auth_router, prefix=prefix, include_in_schema=include_schema)
    app.include_router(iocs_router, prefix=prefix, include_in_schema=include_schema)
    app.include_router(submissions_router, prefix=prefix, include_in_schema=include_schema)
    app.include_router(admin_router, prefix=prefix, include_in_schema=include_schema)
    app.include_router(register_router, prefix=prefix, include_in_schema=include_schema)
    app.include_router(contributor_router, prefix=prefix, include_in_schema=include_schema)
    app.include_router(dashboard_router, prefix=prefix, include_in_schema=include_schema)
