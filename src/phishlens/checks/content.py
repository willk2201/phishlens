"""Language patterns. Phishing relies on pressure: urgency, fear, authority and greed.

Wording alone is weak evidence (real companies send urgent emails too), so these
checks score lower than technical signs like failed authentication or look-alike
domains, and only add up when several appear together.
"""

from __future__ import annotations

import re

from ..models import Email, Finding, Severity
from .base import Context, check

PATTERNS: dict[str, tuple[str, Severity, str, list[str]]] = {
    "urgency": (
        "Urgent or threatening language",
        Severity.LOW,
        "Creates time pressure so you act before thinking it through.",
        [
            r"within \d+ hours?", r"immediately", r"urgent(ly)?", r"act now",
            r"(account|access) (will be|has been) (suspended|closed|locked|restricted|disabled)",
            r"final (notice|warning|reminder)", r"last chance", r"expires? today",
            r"legal action", r"unusual (sign-in|activity|login)",
        ],
    ),
    "credentials": (
        "Asks for passwords or personal details",
        Severity.MEDIUM,
        "Real organisations never ask you to confirm a password or card details by email.",
        [
            r"(verify|confirm|update|validate) (your )?(identity|account|password|details|"
            r"payment|billing|information)",
            r"(enter|provide|re-?enter) (your )?(password|pin|card|bank|login)",
            r"social security|national insurance number|security code|cvv",
        ],
    ),
    "money": (
        "Unusual payment request",
        Severity.MEDIUM,
        "Requests for gift cards, wire transfers or changed bank details are the core of "
        "invoice and CEO fraud.",
        [
            r"gift ?cards?", r"wire transfer", r"(new|updated|changed) bank (details|account)",
            r"bitcoin|crypto(currency)? wallet", r"itunes|steam card|google play card",
        ],
    ),
    "secrecy": (
        "Asks you to keep it secret",
        Severity.MEDIUM,
        "Secrecy stops you checking with a colleague, which is exactly how these scams "
        "get caught.",
        [r"keep this (between us|confidential|to yourself)", r"don'?t (tell|mention)",
         r"(i'?m|i am) (in a meeting|travelling|unavailable)"],
    ),
    "generic": (
        "Generic greeting",
        Severity.INFO,
        "Mass phishing doesn't know your name. On its own this is common in legitimate "
        "newsletters too.",
        [r"\bdear (customer|user|client|member|account holder|sir|madam|valued)"],
    ),
}  # fmt: skip

_COMPILED = {k: [re.compile(p, re.IGNORECASE) for p in v[3]] for k, v in PATTERNS.items()}


@check("PL-C01", "Pressure and manipulation language", "content")
def language(email: Email, ctx: Context) -> list[Finding]:
    haystack = f"{email.subject}\n{email.text}"
    findings = []
    for key, (title, severity, why, _) in PATTERNS.items():
        hits = []
        for pattern in _COMPILED[key]:
            m = pattern.search(haystack)
            if m:
                hits.append(m.group(0).strip())
        if hits:
            quoted = ", ".join(f'"{h}"' for h in dict.fromkeys(hits))
            findings.append(
                Finding("PL-C01", "content", title, severity, why, evidence=quoted[:200])
            )
    return findings
