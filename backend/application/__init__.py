"""Local application-research engine.

This package deliberately does not import the live-network pentest agent.  It
works from immutable, AEGIS-owned artifact snapshots and never executes a
selected artifact during intake or static analysis.
"""

from .service import ApplicationResearchService

__all__ = ["ApplicationResearchService"]
