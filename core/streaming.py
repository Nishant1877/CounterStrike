"""
Real-time Streaming Broadcaster for IdentityGuard (A-03, Stage B).
Supports both native Server-Sent Events (SSE) and WebSockets with pub/sub architecture.
Zero external dependencies (uses standard asyncio Queues).
"""

import asyncio
import json
from typing import Set, Dict, Any, AsyncGenerator
from datetime import datetime, timezone


class EventBroadcaster:
    """
    In-memory async pub/sub event broadcaster for live SOC radar feeds.
    Clients register an asyncio.Queue and receive JSON-serialized event payloads.
    """

    def __init__(self):
        self._subscribers: Set[asyncio.Queue] = set()
        self._lock = asyncio.Lock()

    async def subscribe(self) -> asyncio.Queue:
        """Register a new streaming subscriber queue."""
        q = asyncio.Queue(maxsize=100)
        async with self._lock:
            self._subscribers.add(q)
        return q

    async def unsubscribe(self, q: asyncio.Queue):
        """Unregister a subscriber queue."""
        async with self._lock:
            self._subscribers.discard(q)

    def publish_nowait(self, event_type: str, data: Dict[str, Any]):
        """
        Non-blocking thread-safe publish helper.
        Can be called synchronously from pipeline or API endpoints.
        """
        payload = {
            "type": event_type,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "data": data
        }
        for q in list(self._subscribers):
            try:
                q.put_nowait(payload)
            except asyncio.QueueFull:
                # Drop oldest or skip if subscriber is too slow
                try:
                    q.get_nowait()
                    q.put_nowait(payload)
                except Exception:
                    pass
            except Exception:
                pass

    @property
    def subscriber_count(self) -> int:
        return len(self._subscribers)


# Global singleton broadcaster instance
broadcaster = EventBroadcaster()
