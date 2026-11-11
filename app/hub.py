# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Naby Sidime. LogSonar : https://github.com/NabySidime/LogSonar
"""Diffusion temps réel vers les navigateurs connectés (WebSocket)."""
from __future__ import annotations

import asyncio


class Hub:
    def __init__(self, maxsize: int = 1000) -> None:
        self._subs: set[asyncio.Queue] = set()
        self._maxsize = maxsize

    def subscribe(self) -> asyncio.Queue:
        q: asyncio.Queue = asyncio.Queue(maxsize=self._maxsize)
        self._subs.add(q)
        return q

    def unsubscribe(self, q: asyncio.Queue) -> None:
        self._subs.discard(q)

    @property
    def listeners(self) -> int:
        return len(self._subs)

    def publish(self, kind: str, data) -> None:
        """Non bloquant : un client lent perd les messages les plus anciens."""
        msg = {"type": kind, "data": data}
        for q in list(self._subs):
            if q.full():
                try:
                    q.get_nowait()
                except asyncio.QueueEmpty:
                    pass
            try:
                q.put_nowait(msg)
            except asyncio.QueueFull:
                pass


hub = Hub()
