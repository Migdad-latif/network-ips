"""
rate_limiter.py
---------------
Token bucket rate limiter for the IPS.
Tracks packets-per-second per source IP and
flags IPs that exceed the configured threshold.
"""

import time
import threading
from collections import defaultdict, deque

# ── Configuration ──────────────────────────────────────────────────────────────

DEFAULT_PPS_LIMIT  = 50    # packets per second before flagging
DEFAULT_WINDOW     = 1.0   # sliding window in seconds
CLEANUP_INTERVAL   = 30    # seconds between stale entry cleanup

class RateLimiter:
    """
    Sliding window rate limiter.

    For each source IP, maintains a deque of packet timestamps
    within the last WINDOW seconds. If the count exceeds
    PPS_LIMIT the IP is flagged for blocking.

    Token bucket analogy:
      - Bucket refills at PPS_LIMIT tokens/second
      - Each packet costs 1 token
      - Empty bucket = rate limited
    """

    def __init__(self,
                 pps_limit = DEFAULT_PPS_LIMIT,
                 window    = DEFAULT_WINDOW):

        self.pps_limit  = pps_limit
        self.window     = window
        self.buckets    = defaultdict(deque)   # ip → deque of timestamps
        self.lock       = threading.Lock()
        self.violations = defaultdict(int)     # ip → violation count

        # Start cleanup thread
        threading.Thread(
            target = self._cleanup_thread,
            daemon = True
        ).start()

        print(f"[✓] Rate limiter started — "
              f"limit: {pps_limit} pkt/s per IP")

    def check(self, ip):
        """
        Records a packet from ip and returns:
          True  → rate limit exceeded (should block)
          False → within normal limits
        """
        now = time.time()

        with self.lock:
            bucket = self.buckets[ip]
            bucket.append(now)

            # Slide the window — remove old timestamps
            cutoff = now - self.window
            while bucket and bucket[0] < cutoff:
                bucket.popleft()

            current_rate = len(bucket)

        if current_rate > self.pps_limit:
            with self.lock:
                self.violations[ip] += 1
            return True

        return False

    def get_rate(self, ip):
        """Returns the current packet rate for an IP."""
        now = time.time()
        with self.lock:
            bucket = self.buckets[ip]
            cutoff = now - self.window
            # Count packets within window without modifying deque
            return sum(1 for t in bucket if t >= cutoff)

    def get_top_rates(self, n=10):
        """Returns top N IPs by current packet rate."""
        now = time.time()
        rates = {}
        with self.lock:
            for ip, bucket in self.buckets.items():
                cutoff = now - self.window
                rates[ip] = sum(1 for t in bucket if t >= cutoff)
        return sorted(rates.items(), key=lambda x: -x[1])[:n]

    def reset(self, ip):
        """Clears rate tracking for a specific IP."""
        with self.lock:
            if ip in self.buckets:
                del self.buckets[ip]
            if ip in self.violations:
                del self.violations[ip]

    def _cleanup_thread(self):
        """
        Periodically removes stale entries for IPs
        that have not sent packets recently.
        Prevents memory growth during long sessions.
        """
        while True:
            time.sleep(CLEANUP_INTERVAL)
            now    = time.time()
            cutoff = now - self.window * 10   # 10x window = stale

            with self.lock:
                stale = [
                    ip for ip, bucket in self.buckets.items()
                    if not bucket or bucket[-1] < cutoff
                ]
                for ip in stale:
                    del self.buckets[ip]

            if stale:
                print(f"  [~] Rate limiter cleaned {len(stale)} stale entries")