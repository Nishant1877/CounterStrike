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
from api.routes_replay import router as replay_router
from api.routes_compat import router as compat_router, compat_engine
from api.routes_autonomous import router as autonomous_router
from core.autonomous_worker import AutonomousWorker
from core.autonomous_soar import AutonomousSOAR


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup: Initialize database tables, seed baseline personas, and start autonomous threat hunter
    default_db.init_db()
    from data.seed_demo import seed_demo_database
    from api.routes_ingest import _pipeline
    seed_demo_database(target_pipeline=_pipeline)
    AutonomousWorker.start()
    yield
    # Shutdown
    AutonomousWorker.stop()



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
app.include_router(replay_router)
app.include_router(compat_router)
app.include_router(autonomous_router)


@app.get("/health", tags=["Health"])
@app.get("/api/health", tags=["Health"])
def health_check():
    import os
    gemini_key = os.environ.get("GEMINI_API_KEY", "").strip()
    return {
        "status": "healthy",
        "service": "IdentityGuard A-03 Engine",
        "gemini_enabled": bool(gemini_key),
        "forensic_intelligence": "active" if gemini_key else "offline-heuristic-resilient",
        "active_users": len(compat_engine.user_histories),
        "revoked_sessions_count": len(compat_engine.revoked_sessions)
    }



# Mount static frontend files (Analyst SOC & Protected Bank App)
import os
from fastapi.staticfiles import StaticFiles

static_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "dashboard", "static")
if os.path.exists(static_dir):
    app.mount("/", StaticFiles(directory=static_dir, html=True), name="static")


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("api.main:app", host="0.0.0.0", port=8000, reload=True)
