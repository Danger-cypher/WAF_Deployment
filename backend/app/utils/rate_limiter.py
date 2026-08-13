"""
Redis-based rate limiter for WAF authentication endpoint.
Implements sliding window rate limiting with exponential backoff for brute-force protection.
"""
import time
import logging
from typing import Optional, Tuple
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

try:
    import redis
except ImportError:
    redis = None
    logger.warning("Redis not available. Rate limiting will be disabled.")

from app.config.settings import settings
from app.utils.redis_client import get_global_redis_client, _get_redis_password


class RateLimiter:
    """
    Redis-based rate limiter using sliding window algorithm.
    Tracks requests per IP with exponential backoff on failures.
    Uses cached Redis client instance for persistent connections.
    """
    
    def __init__(
        self,
        host: str = "localhost",
        port: int = 6379,
        db: int = 0,
        max_requests: int = 10,  # Max login attempts per window
        window_seconds: int = 60,  # Window size in seconds
        base_block_minutes: int = 1,  # Initial block duration
        max_block_minutes: int = 60,  # Max block duration (cap)
        multiplier: float = 2.0  # Backoff multiplier
    ):
        self.host = host
        self.port = port
        self.db = db
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.base_block_minutes = base_block_minutes
        self.max_block_minutes = max_block_minutes
        self.multiplier = multiplier
        # Use global cached Redis client for persistent connection
        self._client = get_global_redis_client()
        # In-process fallback state, used only when Redis is unavailable or
        # errors — see check_rate_limit(). Format: {ip: {"window": [ts, ...],
        # "failures": int, "blocked_until": epoch_seconds}}. This backend
        # runs as a single instance (docker-compose.yml has no `replicas:`
        # for it), so an in-memory limiter actually holds here — it just
        # doesn't survive a process restart, unlike the Redis-backed state.
        self._local_fallback = {}

    @property
    def client(self) -> Optional[redis.Redis]:
        """Cached Redis client - single persistent connection."""
        return self._client
    
    def get_key(self, ip: str, prefix: str = "rate_limit") -> str:
        """Generate Redis key for rate limiting."""
        return f"{prefix}:{ip}"
    
    def get_block_key(self, ip: str) -> str:
        """Generate Redis key for blocking status."""
        return f"rate_limit:blocked:{ip}"
    
    def _get_failure_count(self, ip: str) -> int:
        """Get current failure count for an IP."""
        client = self.client
        if not client:
            return 0
        try:
            count = client.get(self.get_block_key(ip))
            return int(count) if count else 0
        except (redis.RedisError, ValueError):
            return 0
    
    def _increment_failure(self, ip: str) -> int:
        """Increment failure count and return new count."""
        client = self.client
        if not client:
            return 0
        try:
            key = self.get_block_key(ip)
            count = client.incr(key)
            client.expire(key, self.max_block_minutes * 60)
            return count
        except redis.RedisError as e:
            logger.error(f"Failed to increment failure count for {ip}: {e}")
            return 0
    
    def _reset_failures(self, ip: str) -> bool:
        """Reset failure count after successful login."""
        client = self.client
        if not client:
            return False
        try:
            client.delete(self.get_block_key(ip))
            return True
        except redis.RedisError:
            return False
    
    def _get_block_duration(self, failures: int) -> int:
        """Calculate block duration based on failure count (exponential backoff)."""
        if failures <= 0:
            return 0
        duration = self.base_block_minutes * (self.multiplier ** (failures - 1))
        return min(int(duration), self.max_block_minutes)
    
    def check_rate_limit(self, ip: str) -> Tuple[bool, dict]:
        """
        Check if IP is rate limited.
        Returns (is_allowed, metadata_dict).
        """
        metadata = {
            "ip": ip,
            "max_requests": self.max_requests,
            "window_seconds": self.window_seconds,
            "is_allowed": True,
            "remaining_requests": self.max_requests,
            "retry_after": None,
            "block_reason": None
        }
        
        client = self.client
        if not client:
            # Redis unavailable — previously this returned (True, ...)
            # unconditionally, i.e. login throttling silently disabled
            # itself during any Redis outage. Fall back to an in-process
            # limiter instead of failing wide open.
            logger.warning(f"Redis unavailable for rate limiting on {ip} — using in-process fallback limiter.")
            return self._check_rate_limit_local(ip, metadata)
        
        # Check if IP is currently blocked
        block_key = self.get_block_key(ip)
        block_count = client.get(block_key)
        
        if block_count:
            failures = int(block_count)
            duration = self._get_block_duration(failures)
            ttl = client.ttl(block_key)
            
            metadata["is_allowed"] = False
            metadata["remaining_requests"] = 0
            metadata["retry_after"] = ttl
            metadata["block_reason"] = f"Too many failed attempts. Block expires in {ttl // 60}m {ttl % 60}s"
            return False, metadata
        
        # Check sliding window rate limit
        now = time.time()
        window_start = now - self.window_seconds
        key = self.get_key(ip)
        
        try:
            # Remove old entries outside the window
            client.zremrangebyscore(key, 0, window_start)
            
            # Count requests in current window
            current_count = client.zcard(key)
            
            metadata["remaining_requests"] = max(0, self.max_requests - current_count)
            
            if current_count >= self.max_requests:
                # Rate limit exceeded
                failures = self._increment_failure(ip)
                block_duration = self._get_block_duration(failures)
                
                metadata["is_allowed"] = False
                metadata["retry_after"] = block_duration * 60
                metadata["block_reason"] = f"Rate limit exceeded. Blocked for {block_duration} minutes."
                
                # Set block key
                client.setex(block_key, block_duration * 60, str(failures))
                
                return False, metadata
            
            # Add current request to window
            pipe = client.pipeline()
            pipe.zadd(key, {f"{now}:{time.time_ns()}": now})
            pipe.expire(key, self.window_seconds * 2)  # Extra buffer
            pipe.execute()
            
            return True, metadata
            
        except redis.RedisError as e:
            logger.error(f"Redis error during rate limit check for {ip}: {e}")
            # Same fail-open-to-fallback fix as the "client is None" branch
            # above — a mid-request Redis error must not grant unlimited
            # attempts either.
            return self._check_rate_limit_local(ip, metadata)

    def _check_rate_limit_local(self, ip: str, metadata: dict) -> Tuple[bool, dict]:
        """
        In-process sliding-window + exponential-backoff limiter mirroring
        check_rate_limit()'s Redis-backed logic, used only while Redis is
        unreachable. Does not persist across a process restart and is
        per-process (fine for this single-instance backend) — it exists to
        avoid the choice between "unlimited login attempts during a Redis
        blip" and "lock every admin out during a Redis blip," not to fully
        replace Redis.
        """
        now = time.time()
        state = self._local_fallback.setdefault(ip, {"window": [], "failures": 0, "blocked_until": 0.0})

        if now < state["blocked_until"]:
            retry_after = int(state["blocked_until"] - now)
            metadata["is_allowed"] = False
            metadata["remaining_requests"] = 0
            metadata["retry_after"] = retry_after
            metadata["block_reason"] = f"Too many failed attempts (fallback limiter). Retry in {retry_after}s."
            return False, metadata

        state["window"] = [t for t in state["window"] if t > now - self.window_seconds]
        metadata["remaining_requests"] = max(0, self.max_requests - len(state["window"]))

        if len(state["window"]) >= self.max_requests:
            state["failures"] += 1
            block_duration = self._get_block_duration(state["failures"])
            state["blocked_until"] = now + block_duration * 60
            metadata["is_allowed"] = False
            metadata["retry_after"] = block_duration * 60
            metadata["block_reason"] = f"Rate limit exceeded (fallback limiter). Blocked for {block_duration} minutes."
            return False, metadata

        state["window"].append(now)
        return True, metadata

    def record_success(self, ip: str) -> bool:
        """Record successful authentication (resets failure count)."""
        if ip in self._local_fallback:
            self._local_fallback[ip] = {"window": [], "failures": 0, "blocked_until": 0.0}
        return self._reset_failures(ip)


# Global rate limiter instance with cached Redis connection
rate_limiter = RateLimiter(
    max_requests=10,      # 10 failed attempts before blocking
    window_seconds=60,    # Per 60 seconds
    base_block_minutes=1, # Start with 1 min block
    max_block_minutes=60, # Cap at 60 minutes
    multiplier=2.0        # Double block time each failure
)
