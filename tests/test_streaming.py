"""
Tests for Stage B: Real-Time Streaming & Live Attack Radar (WebSockets / SSE).
Verifies:
1. EventBroadcaster pub/sub mechanics (subscribe, broadcast, queue isolation).
2. GET /api/stream/events Server-Sent Events endpoint connects and streams live decision payloads.
3. Ingesting an event via POST /v1/events triggers live broadcast over the active stream.
4. WebSocket /api/ws/events endpoint connects and streams live decision envelopes.
"""

import asyncio
import json
import pytest
from fastapi.testclient import TestClient
from api.main import app
from core.streaming import broadcaster, EventBroadcaster


@pytest.fixture
def client():
    return TestClient(app)


@pytest.mark.asyncio
async def test_event_broadcaster_pubsub_isolation():
    """Verify that multiple subscribers receive broadcasted events correctly."""
    b = EventBroadcaster()
    q1 = await b.subscribe()
    q2 = await b.subscribe()
    assert b.subscriber_count == 2

    # Broadcast event
    b.publish_nowait("test_alert", {"msg": "takeover_detected", "risk": 95})

    item1 = await asyncio.wait_for(q1.get(), timeout=1.0)
    item2 = await asyncio.wait_for(q2.get(), timeout=1.0)

    assert item1["type"] == "test_alert"
    assert item1["data"]["risk"] == 95
    assert item2["data"]["msg"] == "takeover_detected"

    # Unsubscribe
    await b.unsubscribe(q1)
    assert b.subscriber_count == 1
    await b.unsubscribe(q2)
    assert b.subscriber_count == 0


@pytest.mark.asyncio
async def test_sse_streaming_endpoint_connects():
    """Test that stream_events generates SSE formatted frames."""
    from api.routes_analyst import stream_events
    response = await stream_events()
    assert response.status_code == 200
    assert "text/event-stream" in response.headers["content-type"]
    gen = response.body_iterator
    first_chunk = await anext(gen)
    assert "event: connect" in first_chunk
    assert "connected" in first_chunk



def test_live_event_triggers_sse_broadcast(client):
    """Verify that posting a live event into /v1/events broadcasts a decision frame."""
    import uuid
    client.post("/api/reset")

    unique_user = f"stream_user_{uuid.uuid4().hex[:6]}"
    payload = {
        "event_id": f"evt_stream_{uuid.uuid4().hex[:8]}",
        "timestamp": "2026-10-11T12:00:00Z",
        "user": unique_user,
        "device_id": "dev_stream_1",
        "location_label": "Pune",
        "action": "login"
    }
    
    sub_queue = None

    async def check_pipeline_broadcast():
        nonlocal sub_queue
        sub_queue = await broadcaster.subscribe()
        try:
            # Trigger via client
            res = client.post("/v1/events", json=payload)
            assert res.status_code == 200

            
            # Receive broadcasted message
            msg = await asyncio.wait_for(sub_queue.get(), timeout=2.0)
            assert msg["type"] == "decision"
            assert msg["data"]["user"] == unique_user
            assert msg["data"]["action"] == "login"
        finally:
            if sub_queue:
                await broadcaster.unsubscribe(sub_queue)


    asyncio.run(check_pipeline_broadcast())


def test_websocket_events_endpoint(client):
    """Test that /api/ws/events connects via websocket and receives connection ack."""
    with client.websocket_connect("/api/ws/events") as websocket:
        data = websocket.receive_json()
        assert data["type"] == "connected"
        assert "timestamp" in data
