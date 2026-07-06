"""
Potatoo Core — Smart Rate Limiter
Mimics human-like browsing patterns to avoid detection/banning.
"""

import time
import random
import threading
from collections import defaultdict, deque


class RateLimiter:
    """
    Thread-safe rate limiter with:
    - Random jitter to mimic human behavior
    - Per-host request tracking
    - Auto-backoff on 429/503 responses
    - Configurable concurrency
    """

    def __init__(
        self,
        min_delay: float = 0.5,
        max_delay: float = 2.0,
        max_threads: int = 3,
        backoff_on_429: float = 30.0,
        requests_per_minute: int = 60,
    ):
        self.min_delay       = min_delay
        self.max_delay       = max_delay
        self.backoff_on_429  = backoff_on_429
        self.rpm_limit       = requests_per_minute
        self._semaphore      = threading.Semaphore(max_threads)
        self._lock           = threading.Lock()
        self._last_request   = defaultdict(float)      # host → timestamp
        self._request_times  = defaultdict(deque)      # host → deque of timestamps
        self._backoff_until  = defaultdict(float)      # host → backoff end timestamp
        self._total_requests = 0
        self._total_backoffs = 0

    def _get_host(self, url: str) -> str:
        """Extract host from URL."""
        try:
            from urllib.parse import urlparse
            return urlparse(url).netloc
        except Exception:
            return url

    def wait(self, url: str = ""):
        """
        Call before each request. Enforces delay + rate limiting.
        Blocks until it is safe to make the next request.
        """
        host = self._get_host(url) if url else "default"

        with self._lock:
            # Check backoff
            now = time.time()
            if now < self._backoff_until[host]:
                wait_time = self._backoff_until[host] - now
                time.sleep(wait_time)
                now = time.time()

            # Enforce RPM limit using sliding window
            minute_ago = now - 60
            rq = self._request_times[host]
            while rq and rq[0] < minute_ago:
                rq.popleft()

            if len(rq) >= self.rpm_limit:
                # Wait until oldest request is > 60s old
                sleep_needed = 60 - (now - rq[0]) + 0.1
                if sleep_needed > 0:
                    time.sleep(sleep_needed)
                    now = time.time()

            # Enforce per-request delay with jitter
            elapsed = now - self._last_request[host]
            delay   = random.uniform(self.min_delay, self.max_delay)
            if elapsed < delay:
                time.sleep(delay - elapsed)
                now = time.time()

            self._last_request[host] = now
            self._request_times[host].append(now)
            self._total_requests += 1

    def notify_response(self, url: str, status_code: int):
        """
        Call after each response to handle backoff conditions.
        """
        host = self._get_host(url)
        if status_code in (429, 503):
            with self._lock:
                self._backoff_until[host] = time.time() + self.backoff_on_429
                self._total_backoffs += 1

    def acquire(self):
        """Acquire concurrency slot."""
        self._semaphore.acquire()

    def release(self):
        """Release concurrency slot."""
        self._semaphore.release()

    def __enter__(self):
        self.acquire()
        return self

    def __exit__(self, *args):
        self.release()

    def get_stats(self) -> dict:
        return {
            "total_requests": self._total_requests,
            "total_backoffs": self._total_backoffs,
        }

    def set_aggressive(self):
        """Speed up for trusted/local targets."""
        self.min_delay = 0.1
        self.max_delay = 0.5

    def set_stealth(self):
        """Slow down for production targets."""
        self.min_delay = 2.0
        self.max_delay = 5.0
