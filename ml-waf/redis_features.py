import logging
import redis
import os

# Configure logger
logger = logging.getLogger(__name__)

_REDIS_SECRET_FILE = "/etc/cybersentinel/redis.secret"


def _get_redis_password() -> str:
    """Reads the Redis password from environment variable or falls back to a secret file."""
    env_password = os.environ.get("REDIS_PASSWORD")
    if env_password:
        return env_password.strip()
    try:
        with open(_REDIS_SECRET_FILE, "r") as f:
            return f.read().strip()
    except FileNotFoundError:
        logger.warning(
            f"Redis secret file not found at {_REDIS_SECRET_FILE}. "
            "Connecting without authentication."
        )
        return ""
    except Exception as e:
        logger.error(f"Failed to read Redis secret file: {e}")
        return ""


_redis_password = _get_redis_password()

# Standard Redis connection setup. Setting aggressive timeouts to prevent blocking FastAPI responses.
r = redis.Redis(
    host=os.environ.get("REDIS_HOST", "localhost"),
    port=6379,
    db=0,
    password=_redis_password if _redis_password else None,
    socket_timeout=0.05,
    socket_connect_timeout=0.05
)

def increment_request_counters(ip: str):
    """
    Increments time-window request counters atomically using a Redis transaction pipeline.
    Ensures keys have appropriate TTLs.
    """
    try:
        pipe = r.pipeline()
        
        # rpm: 1-minute tracking (Key: rpm:{ip}, TTL: 60s)
        pipe.incr(f"rpm:{ip}")
        pipe.ttl(f"rpm:{ip}")
        
        # r5m: 5-minute footprint tracking (Key: r5m:{ip}, TTL: 300s)
        pipe.incr(f"r5m:{ip}")
        pipe.ttl(f"r5m:{ip}")
        
        # r1h: 1-hour advanced recon profiling (Key: r1h:{ip}, TTL: 3600s)
        pipe.incr(f"r1h:{ip}")
        pipe.ttl(f"r1h:{ip}")
        
        results = pipe.execute()
        
        # Check if TTL is -1 (no expiration set, i.e. key was just created) and set expiration
        pipe2 = r.pipeline()
        if results[1] == -1:
            pipe2.expire(f"rpm:{ip}", 60)
        if results[3] == -1:
            pipe2.expire(f"r5m:{ip}", 300)
        if results[5] == -1:
            pipe2.expire(f"r1h:{ip}", 3600)
        pipe2.execute()
    except redis.RedisError as e:
        logger.warning(f"Redis request counter update failed for IP {ip}: {e}")

def increment_reputation(ip: str):
    """
    Increments threat reputation by +1.0 for confirmed blocks.
    Enforces a 24-hour TTL (86400s) on key creation or update.
    """
    try:
        pipe = r.pipeline()
        pipe.incrbyfloat(f"rep:{ip}", 1.0)
        pipe.expire(f"rep:{ip}", 86400)
        pipe.execute()
    except redis.RedisError as e:
        logger.warning(f"Redis reputation increment failed for IP {ip}: {e}")

def decay_reputation(ip: str):
    """
    Decrements threat reputation by -0.1 for clean overrides.
    This is atomic and prevents race conditions.
    """
    try:
        # Subtract 0.1 (increment by -0.1)
        r.incrbyfloat(f"rep:{ip}", -0.1)
        r.expire(f"rep:{ip}", 86400)
    except redis.RedisError as e:
        logger.warning(f"Redis reputation decay failed for IP {ip}: {e}")

def save_abuse_score(ip: str, score: float):
    """
    Caches the AbuseIPDB abuse score in Redis with a 24-hour TTL (86400s).
    """
    try:
        r.setex(f"abuse:{ip}", 86400, float(score))
    except redis.RedisError as e:
        logger.warning(f"Failed to cache abuse score for IP {ip}: {e}")

def get_redis_metrics(ip: str) -> tuple[float, float, any]:
    """
    Retrieves the 1-minute request rate (rpm), threat reputation (rep), and cached abuse score
    in a single pipeline. Clamps reputation at 0.0. If Redis connection drops or times out,
    defaults metrics to 0.0 and returns None for abuse score.
    """
    try:
        pipe = r.pipeline()
        pipe.get(f"rpm:{ip}")
        pipe.get(f"rep:{ip}")
        pipe.get(f"abuse:{ip}")
        rpm_val, rep_val, abuse_val = pipe.execute()
        
        rpm = float(rpm_val) if rpm_val is not None else 0.0
        rep = float(rep_val) if rep_val is not None else 0.0
        
        # Post-read clamp to zero to clean up negative floats from decrbyfloat
        if rep < 0.0:
            r.set(f"rep:{ip}", 0.0)
            r.expire(f"rep:{ip}", 86400)
            rep = 0.0
            
        abuse_score = float(abuse_val) if abuse_val is not None else None
        return rpm, rep, abuse_score
    except (redis.RedisError, ValueError, TypeError) as e:
        # Silently degrade to zero scores to avoid breaking WAF request processing
        logger.warning(f"Redis metrics fetch failed for IP {ip}. Defaulting to 0.0. Error: {e}")
        return 0.0, 0.0, None
