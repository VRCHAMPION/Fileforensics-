"""In-memory per-IP token bucket. Single process only - see SECURITY.md."""

from __future__ import annotations

import threading
import time
from collections import OrderedDict


class TokenBucketLimiter:
    def __init__(self, rate_per_minute: int, burst: int, max_clients: int = 10_000, clock=time.monotonic):
        self.rate = max(rate_per_minute, 1) / 60.0  # tokens per second
        self.capacity = float(max(burst, 1))
        self.max_clients = max_clients
        self._clock = clock
        self._buckets: OrderedDict[str, tuple[float, float]] = OrderedDict()
        self._lock = threading.Lock()

    def allow(self, key: str) -> tuple[bool, float]:
        """Take one token for ``key``. Returns (allowed, seconds until next token)."""
        now = self._clock()
        with self._lock:
            tokens, last = self._buckets.pop(key, (self.capacity, now))
            tokens = min(self.capacity, tokens + (now - last) * self.rate)
            if tokens >= 1.0:
                tokens -= 1.0
                allowed, retry = True, 0.0
            else:
                allowed, retry = False, (1.0 - tokens) / self.rate
            self._buckets[key] = (tokens, now)
            # LRU eviction keeps memory bounded if someone sprays source addresses.
            while len(self._buckets) > self.max_clients:
                self._buckets.popitem(last=False)
            return allowed, retry

    def __len__(self) -> int:
        return len(self._buckets)
