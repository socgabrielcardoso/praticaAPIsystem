from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass
from typing import Generic, TypeVar

T = TypeVar("T")


@dataclass(slots=True)
class _Entry(Generic[T]):
    expires_at: float
    value: T


class TTLCache(Generic[T]):
    def __init__(self, ttl_seconds: int) -> None:
        self._ttl_seconds = ttl_seconds
        self._items: dict[str, _Entry[T]] = {}
        self._lock = asyncio.Lock()

    async def get(self, key: str) -> T | None:
        if self._ttl_seconds <= 0:
            return None
        now = time.monotonic()
        async with self._lock:
            entry = self._items.get(key)
            if entry is None:
                return None
            if entry.expires_at <= now:
                self._items.pop(key, None)
                return None
            return entry.value

    async def set(self, key: str, value: T) -> None:
        if self._ttl_seconds <= 0:
            return
        async with self._lock:
            self._items[key] = _Entry(
                expires_at=time.monotonic() + self._ttl_seconds,
                value=value,
            )
