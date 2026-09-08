"""In-process async pub/sub used to stream live events to WebSocket clients."""
from __future__ import annotations

import asyncio
from typing import Any


class EventBus:
    def __init__(self) -> None:
        self._subscribers: set[asyncio.Queue] = set()
        self._loop: asyncio.AbstractEventLoop | None = None

    def bind_loop(self, loop: asyncio.AbstractEventLoop) -> None:
        self._loop = loop

    def subscribe(self) -> asyncio.Queue:
        q: asyncio.Queue = asyncio.Queue(maxsize=200)
        self._subscribers.add(q)
        return q

    def unsubscribe(self, q: asyncio.Queue) -> None:
        self._subscribers.discard(q)

    async def publish(self, message: dict[str, Any]) -> None:
        for q in list(self._subscribers):
            try:
                q.put_nowait(message)
            except asyncio.QueueFull:
                pass  # slow client — drop rather than block the pipeline

    def publish_threadsafe(self, message: dict[str, Any]) -> None:
        """Publish from a non-async worker thread (scanner, scheduler)."""
        if self._loop and self._loop.is_running():
            asyncio.run_coroutine_threadsafe(self.publish(message), self._loop)


bus = EventBus()
