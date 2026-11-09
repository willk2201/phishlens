"""Check registry. A check is a pure function ``(Email, Context) -> list[Finding]``."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from ..domains import DEFAULT_BRANDS
from ..models import Email, Finding


@dataclass
class Context:
    """Settings that checks may need, such as the brands to protect."""

    brands: tuple[str, ...] = DEFAULT_BRANDS


CheckFn = Callable[[Email, Context], list[Finding]]


@dataclass(frozen=True)
class Check:
    id: str
    title: str
    category: str
    fn: CheckFn


REGISTRY: list[Check] = []


def check(id: str, title: str, category: str):
    def register(fn: CheckFn) -> CheckFn:
        REGISTRY.append(Check(id, title, category, fn))
        return fn

    return register
