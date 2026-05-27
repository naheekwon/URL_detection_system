import time
from collections import defaultdict, deque


class InMemoryRateLimiter:
    def __init__(self, max_requests, window_seconds):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.requests = defaultdict(deque)

    def allow(self, key):
        now = time.time()
        bucket = self.requests[key]
        cutoff = now - self.window_seconds

        while bucket and bucket[0] < cutoff:
            bucket.popleft()

        if len(bucket) >= self.max_requests:
            retry_after = max(1, int(self.window_seconds - (now - bucket[0])))
            return False, retry_after

        bucket.append(now)
        return True, 0
