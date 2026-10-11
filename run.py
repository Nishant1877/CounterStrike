"""
1-Click Server Launcher for IdentityGuard (A-03, Domain 2).
Initializes database tables, pre-seeds demonstration scenarios (Asha, David, Elena),
and launches the FastAPI server with Analyst Dashboard & Target Banking App.
"""

import uvicorn
from store.db import default_db
from data.seed_demo import seed_demo_database

if __name__ == "__main__":
    print("==================================================================")
    print("  IDENTITYGUARD (A-03): SESSION RISK & TAKEOVER DETECTION ENGINE  ")
    print("==================================================================")
    
    # 1. Seed demo database with rich personas
    seed_demo_database()
    
    print("\n[+] Launching server on http://127.0.0.1:8000")
    print("    - Analyst SOC Command Center:   http://127.0.0.1:8000/")
    print("    - React 18 World Threat Map UI: http://127.0.0.1:8000/react_app.html")
    print("    - Protected Target Banking App: http://127.0.0.1:8000/bank_app.html")
    print("    - Interactive API Docs:         http://127.0.0.1:8000/docs")
    print("==================================================================\n")
    
    uvicorn.run("api.main:app", host="127.0.0.1", port=8000, reload=False)
