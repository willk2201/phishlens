"""Run every check against a parsed email."""

from __future__ import annotations

from pathlib import Path

from .checks import REGISTRY, Context
from .models import Analysis, Email
from .parse import parse_file


def analyse(email: Email, ctx: Context | None = None, source: str = "") -> Analysis:
    ctx = ctx or Context()
    findings = [f for c in REGISTRY for f in c.fn(email, ctx)]
    findings.sort(key=lambda f: (-f.severity.rank, f.check_id))
    return Analysis(email=email, findings=findings, source=source)


def analyse_file(path: str | Path, ctx: Context | None = None) -> Analysis:
    return analyse(parse_file(path), ctx, source=str(path))
