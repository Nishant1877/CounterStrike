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
    
    import os
    import socket

    def is_port_in_use(port: int) -> bool:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            return s.connect_ex(('127.0.0.1', port)) == 0

    default_port = int(os.environ.get("PORT", "8000"))
    if is_port_in_use(default_port) and "PORT" not in os.environ:
        default_port = 8080

    print(f"\n[+] Launching server on http://127.0.0.1:{default_port}")
    print(f"    - Analyst SOC Command Center:   http://127.0.0.1:{default_port}/")
    print(f"    - React 18 World Threat Map UI: http://127.0.0.1:{default_port}/react_app.html")
    print(f"    - Protected Target Banking App: http://127.0.0.1:{default_port}/bank_app.html")
    print(f"    - Interactive API Docs:         http://127.0.0.1:{default_port}/docs")
    print("==================================================================\n")
    
    uvicorn.run("api.main:app", host="127.0.0.1", port=default_port, reload=False)

