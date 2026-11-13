"""rate.py - Global rate limiter and max-requests counter.

Every HTTP request reconlite makes goes through one shared RateLimiter, so
the safety limits apply across all modules, not per module.
"""
from __future__ import annotations

import threading
import time

MIN_DELAY = 0.2              # seconds between requests (lab minimum: 200 ms)
DEFAULT_MAX_REQUESTS = 500   # hard ceiling on total requests per run


class RequestCapReached(Exception):
    """Raised when the run has used up its request budget."""


class RateLimiter:
    def __init__(self, delay: float = MIN_DELAY, max_requests: int = DEFAULT_MAX_REQUESTS):
        if delay < MIN_DELAY:
            raise ValueError(f"delay must be at least {MIN_DELAY} seconds (got {delay})")
        if not 1 <= max_requests <= DEFAULT_MAX_REQUESTS:
            raise ValueError(f"max_requests must be between 1 and {DEFAULT_MAX_REQUESTS} (got {max_requests})")
        self.delay = delay
        self.max_requests = max_requests
        self.count = 0
        self._last: float | None = None
        self._lock = threading.Lock()

    def acquire(self) -> None:
        """Block until the next request is allowed, or raise if the cap is hit."""
        with self._lock:
            if self.count >= self.max_requests:
                raise RequestCapReached(f"request cap of {self.max_requests} reached")
            if self._last is not None:
                wait = self.delay - (time.monotonic() - self._last)
                if wait > 0:
                    time.sleep(wait)
            self._last = time.monotonic()
            self.count += 1

    @property
    def remaining(self) -> int:
        return self.max_requests - self.count
