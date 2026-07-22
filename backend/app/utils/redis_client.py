"""
Centralized Redis client configuration for WAF.
This module ensures consistent Redis connection handling across all services.
"""
import logging
import os
from typing import Optional

logger = logging.getLogger(__name__)

try:
    import redis
    REDIS_AVAILABLE = True
except ImportError:
    REDIS_AVAILABLE = False
    logger.warning("Redis not available. Redis features will be disabled.")


def _get_redis_password() -> Optional[str]:
    """
    Get Redis password from environment variable or config file.
    Priority: 1) REDIS_PASSWORD env, 2) /etc/cybersentinel/redis.secret file
    """
    # Try environment variable first
    env_password = os.environ.get("REDIS_PASSWORD")
    if env_password:
        return env_password.strip() if env_password else None

    # Fallback to file
    secret_file_path = "/etc/cybersentinel/redis.secret"  # nosec B105
    try:
        if os.path.exists(secret_file_path):
            with open(secret_file_path, "r") as f:
                password = f.read().strip()
                return password if password else None
    except (IOError, OSError) as e:
        logger.warning(f"Failed to read Redis secret file: {e}")

    return None


def get_redis_client(
    host: str = None,
    port: int = None,
    db: int = 0,
    socket_timeout: float = 2.0,
    socket_connect_timeout: float = 2.0,
    decode_responses: bool = True
) -> Optional[redis.Redis]:
    """
    Get a Redis client instance with consistent configuration.
    
    Args:
        host: Redis host (default: localhost or REDIS_HOST env)
        port: Redis port (default: 6379)
        db: Redis database number (default: 0)
        socket_timeout: Socket timeout in seconds (default: 2.0)
        socket_connect_timeout: Connection timeout in seconds (default: 2.0)
        decode_responses: Whether to decode responses to strings (default: True)
    
    Returns:
        Redis client instance or None if Redis is not available
    """
    if not REDIS_AVAILABLE:
        logger.warning("Redis library not imported")
        return None

    # Get configuration
    redis_host = host or os.environ.get("REDIS_HOST", "localhost")
    redis_port = port or 6379
    redis_password = _get_redis_password()

    try:
        client = redis.Redis(
            host=redis_host,
            port=redis_port,
            db=db,
            password=redis_password if redis_password else None,
            socket_timeout=socket_timeout,
            socket_connect_timeout=socket_connect_timeout,
            decode_responses=decode_responses
        )
        # Test connection
        client.ping()
        logger.info(f"Redis client connected to {redis_host}:{redis_port}")
        return client
    except redis.ConnectionError as e:
        logger.error(f"Failed to connect to Redis at {redis_host}:{redis_port}: {e}")
        return None
    except Exception as e:
        logger.error(f"Unexpected Redis connection error: {e}")
        return None


# Global client instance for convenience
_redis_client: Optional[redis.Redis] = None


def get_global_redis_client() -> Optional[redis.Redis]:
    """
    Get or create a global Redis client instance.
    Useful for services that need a single shared connection.
    """
    global _redis_client
    if _redis_client is None:
        _redis_client = get_redis_client()
    return _redis_client


# Cache the redis connection check result to avoid connecting on every request
_redis_cache_result: Optional[bool] = None
_redis_cache_time: float = 0.0
_REDIS_CACHE_TTL: float = 30.0  # seconds


def validate_redis_connection() -> bool:
    """
    Test Redis connection and return status.
    Result is cached for 30 seconds to avoid blocking on every health check.
    """
    global _redis_cache_result, _redis_cache_time
    import time
    now = time.monotonic()
    if _redis_cache_result is not None and (now - _redis_cache_time) < _REDIS_CACHE_TTL:
        return _redis_cache_result

    client = get_redis_client(socket_timeout=1.0, socket_connect_timeout=1.0)
    try:
        if client is None:
            _redis_cache_result = False
        else:
            client.ping()
            _redis_cache_result = True
    except Exception:
        _redis_cache_result = False

    _redis_cache_time = now
    return _redis_cache_result
