"""
Optional cloud intelligence: IP reputation refresh from the Arcis
intelligence service. Opt-in, fail-open, locally cached.
"""

from .client import IntelligenceClient, reputation_severity_tier
from .types import IntelligenceOptions, IpReputation

__all__ = [
    "IntelligenceClient",
    "IntelligenceOptions",
    "IpReputation",
    "reputation_severity_tier",
]
