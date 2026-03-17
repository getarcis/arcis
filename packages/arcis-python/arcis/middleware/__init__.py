"""
Arcis middleware package.
"""

from .main import Arcis
from .rate_limit import RateLimiter, RateLimitExceeded
from .headers import SecurityHeaders
from .error_handler import ErrorHandler, create_error_handler
from .cors import SafeCors, create_cors
from .cookies import SecureCookieDefaults, create_secure_cookies
from .rate_limit_sliding import SlidingWindowLimiter
from .rate_limit_token import TokenBucketLimiter
from .bot_detection import BotProtection, BotDenied, BotDetectionResult, detect_bot

__all__ = [
    "Arcis",
    "RateLimiter",
    "RateLimitExceeded",
    "SecurityHeaders",
    "ErrorHandler",
    "create_error_handler",
    "SafeCors",
    "create_cors",
    "SecureCookieDefaults",
    "create_secure_cookies",
    "SlidingWindowLimiter",
    "TokenBucketLimiter",
    "BotProtection",
    "BotDenied",
    "BotDetectionResult",
    "detect_bot",
]
