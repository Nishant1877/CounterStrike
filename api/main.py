"""
FastAPI Application Entry Point for IdentityGuard (A-03).
Mounts API endpoints, configures CORS, and initializes database tables.
"""

from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from store.db import default_db
from api.routes_ingest import router as ingest_router
from api.routes_sessions import router as sessions_router
from api.routes_analyst import router as analyst_router


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup: Initialize database tables
    default_db.init_db()
    yield
    # Shutdown


app = FastAPI(
    title="IdentityGuard API",
    description="Session Risk and Account-Takeover Detection Engine (A-03, Domain 2)",
    version="2.0.0",
    lifespan=lifespan
)

# CORS configuration for local dashboard access
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include routers
app.include_router(ingest_router)
app.include_router(sessions_router)
app.include_router(analyst_router)


@app.get("/health", tags=["Health"])
def health_check():
    return {"status": "healthy", "service": "IdentityGuard A-03"}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("api.main:app", host="0.0.0.0", port=8000, reload=True)
