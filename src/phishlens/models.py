"""Core data types: a parsed email, and the warning signs found in it."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"

    @property
    def rank(self) -> int:
        return list(Severity).index(self)

    @property
    def points(self) -> int:
        """How much one finding of this severity adds to the risk score."""
        return {"info": 0, "low": 8, "medium": 18, "high": 35}[self.value]


@dataclass(frozen=True)
class Link:
    href: str  # where the link actually goes
    text: str  # what the reader sees ("" for bare URLs in plain text)


@dataclass(frozen=True)
class Attachment:
    filename: str
    content_type: str
    size: int


@dataclass
class Email:
    """The parts of an email that matter for phishing analysis."""

    subject: str
    from_name: str
    from_address: str
    reply_to: str | None
    return_path: str | None
    auth_results: str | None  # Authentication-Results header added by the receiving server
    text: str  # plain-text body (HTML converted to text if that's all there is)
    links: list[Link] = field(default_factory=list)
    attachments: list[Attachment] = field(default_factory=list)

    @property
    def from_domain(self) -> str:
        return self.from_address.rpartition("@")[2].lower()


@dataclass
class Finding:
    check_id: str
    category: str  # "authentication" | "sender" | "links" | "content" | "attachments"
    title: str
    severity: Severity
    explanation: str  # why this is a warning sign, in plain English
    evidence: str = ""

    def to_dict(self) -> dict:
        return {
            "check_id": self.check_id,
            "category": self.category,
            "title": self.title,
            "severity": self.severity.value,
            "explanation": self.explanation,
            "evidence": self.evidence,
        }


VERDICTS = (
    (55, "Likely phishing"),
    (25, "Suspicious"),
    (0, "Likely safe"),
)


@dataclass
class Analysis:
    email: Email
    findings: list[Finding]
    source: str = ""

    @property
    def score(self) -> int:
        """Risk score 0-100: the sum of finding points, capped at 100."""
        return min(100, sum(f.severity.points for f in self.findings))

    @property
    def verdict(self) -> str:
        return next(label for threshold, label in VERDICTS if self.score >= threshold)

    @property
    def by_severity(self) -> dict[Severity, int]:
        counts = {s: 0 for s in reversed(Severity)}
        for f in self.findings:
            counts[f.severity] += 1
        return counts
