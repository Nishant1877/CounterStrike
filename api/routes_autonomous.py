"""
REST API Routes for Zero-Manpower Autonomous Cyber Defense.
Provides management, metrics, live actions feed, and self-driving demonstration triggers.
"""

from __future__ import annotations
from typing import Dict, Any, List, Optional
from pydantic import BaseModel
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from store.db import default_db
from core.autonomous_soar import AutonomousSOAR
from core.autonomous_worker import AutonomousWorker

router = APIRouter(prefix="/api/autonomous", tags=["Autonomous Zero-Manpower Defense"])


def get_db():
    with default_db.session_scope() as session:
        yield session


class AutonomousToggleRequest(BaseModel):
    enabled: bool


@router.get("/status")
def get_autonomous_status():
    """GET /api/autonomous/status: Returns live autonomous defense status and mitigation metrics."""
    metrics = AutonomousSOAR.get_metrics()
    metrics["self_driving_demo_active"] = AutonomousWorker.is_self_driving_enabled()
    metrics["background_hunter_active"] = AutonomousWorker.is_running()
    return metrics


@router.post("/toggle")
def toggle_autonomous_mode(req: AutonomousToggleRequest):
    """POST /api/autonomous/toggle: Turn 100% Autonomous Mode ON or OFF."""
    AutonomousSOAR.set_autonomous_mode(req.enabled)
    return {
        "status": "success",
        "autonomous_mode": AutonomousSOAR.is_autonomous_enabled(),
        "message": "Autonomous Zero-Manpower defense is now " + ("ENABLED" if req.enabled else "DISABLED")
    }


@router.post("/self-driving/toggle")
def toggle_self_driving(req: AutonomousToggleRequest):
    """POST /api/autonomous/self-driving/toggle: Enable hands-free background chaos attacks and defense."""
    AutonomousWorker.set_self_driving(req.enabled)
    return {
        "status": "success",
        "self_driving_active": AutonomousWorker.is_self_driving_enabled(),
        "message": "Autonomous Self-Driving Demo is now " + ("RUNNING" if req.enabled else "STOPPED")
    }


@router.post("/demo-pulse")
async def trigger_autonomous_pulse():
    """POST /api/autonomous/demo-pulse: Trigger an immediate self-driving attack/defense pulse for judges."""
    pulse_res = await AutonomousWorker.execute_self_driving_pulse()
    return {
        "status": "success",
        "pulse": pulse_res
    }


@router.get("/actions")
def list_autonomous_actions(limit: int = 50):
    """GET /api/autonomous/actions: Retrieve log of recent automated mitigations (kill-switch, quarantine, etc.)."""
    return AutonomousSOAR.get_actions_log(limit=limit)


@router.get("/quarantine")
def list_quarantine_and_blacklist():
    """GET /api/autonomous/quarantine: View current automatically isolated devices and blacklisted IP ranges."""
    return {
        "quarantined_devices": list(AutonomousSOAR._quarantined_devices),
        "blacklisted_ips": list(AutonomousSOAR._blacklisted_ips),
        "total_isolated_hosts": len(AutonomousSOAR._quarantined_devices) + len(AutonomousSOAR._blacklisted_ips)
    }
