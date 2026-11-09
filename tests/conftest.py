from __future__ import annotations

from pathlib import Path

import pytest

from phishlens.checks import Context
from phishlens.domains import DEFAULT_BRANDS
from phishlens.models import Attachment, Email, Link

SAMPLES = Path(__file__).resolve().parent.parent / "samples"
BANK = "northwind-bank.example"
CTX = Context(brands=(*DEFAULT_BRANDS, BANK))


def make_email(**overrides) -> Email:
    """A clean, legitimate-looking email. Tests override one thing at a time."""
    base = dict(
        subject="Team update",
        from_name="Northwind Bank",
        from_address=f"news@{BANK}",
        reply_to=None,
        return_path=f"news@{BANK}",
        auth_results="mx.test; spf=pass; dkim=pass; dmarc=pass",
        text="Hello Alex, here is this month's update.",
        links=[],
        attachments=[],
    )
    base.update(overrides)
    return Email(**base)


def link(href: str, text: str = "") -> Link:
    return Link(href, text)


def attachment(name: str) -> Attachment:
    return Attachment(name, "application/octet-stream", 100)


@pytest.fixture
def samples() -> Path:
    return SAMPLES
