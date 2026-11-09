"""All checks register themselves on import via the ``@check`` decorator."""

from . import attachments, auth, content, links, sender  # noqa: F401  (registration)
from .base import REGISTRY, Check, Context

__all__ = ["REGISTRY", "Check", "Context"]
