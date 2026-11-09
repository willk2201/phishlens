"""Sender authentication: SPF, DKIM and DMARC.

When an email arrives, the receiving mail server checks:

* **SPF**: was it sent from a server the sender's domain allows?
* **DKIM**: is it cryptographically signed by the sender's domain, unaltered?
* **DMARC**: does the visible From domain line up with what passed SPF/DKIM, and what
  does the domain owner want done with failures?

The server records the outcome in an ``Authentication-Results`` header. PhishLens
reads that header; it does not repeat the DNS lookups itself.
"""

from __future__ import annotations

import re

from ..models import Email, Finding, Severity
from .base import Context, check

_RESULT = re.compile(r"\b(spf|dkim|dmarc)\s*=\s*(\w+)", re.IGNORECASE)

EXPLAIN = {
    ("spf", "fail"): "The email was sent from a server that {d} explicitly does not "
    "authorise, so the sender address is probably forged.",
    ("spf", "softfail"): "The email was sent from a server {d} does not list as "
    "authorised. Weaker than a hard fail, but still a warning sign.",
    (
        "spf",
        "none",
    ): "{d} publishes no SPF record, so there's no way to check which servers may send its email.",
    (
        "dkim",
        "fail",
    ): "The email's digital signature is invalid, so it may have been forged "
    "or altered in transit.",
    (
        "dkim",
        "none",
    ): "The email carries no digital signature from the sender's domain.",
    (
        "dmarc",
        "fail",
    ): "The visible From address ({d}) is not backed by a passing SPF or "
    "DKIM check. This is the strongest sign the sender is being impersonated.",
    ("dmarc", "none"): "{d} publishes no DMARC policy, so receiving servers have no "
    "instruction to reject forged email that claims to be from it.",
}
_FALLBACK = "{m} returned '{r}', so the sender could not be verified."
_BAD = {"fail", "softfail", "permerror", "none", "neutral"}


def parse_auth_results(header: str) -> dict[str, str]:
    """``spf=pass ...; dkim=fail ...; dmarc=fail ...`` -> {"spf": "pass", ...} (first wins)."""
    out: dict[str, str] = {}
    for mech, result in _RESULT.findall(header):
        out.setdefault(mech.lower(), result.lower())
    return out


@check("PL-A01", "Sender authentication (SPF / DKIM / DMARC)", "authentication")
def authentication(email: Email, ctx: Context) -> list[Finding]:
    if not email.auth_results:
        return [
            Finding(
                "PL-A01",
                "authentication",
                "No authentication results",
                Severity.INFO,
                "The email has no Authentication-Results header, so SPF/DKIM/DMARC can't be "
                "assessed. This is normal for emails exported from some clients or saved "
                "before delivery.",
            )
        ]

    results = parse_auth_results(email.auth_results)
    findings = []
    for mech in ("dmarc", "spf", "dkim"):
        result = results.get(mech)
        if result is None or result not in _BAD:
            continue
        if mech == "dmarc" and result == "fail":
            severity = Severity.HIGH
        elif result in ("fail", "permerror"):
            severity = Severity.MEDIUM
        else:  # softfail / none / neutral: weaker signal
            severity = Severity.LOW
        findings.append(
            Finding(
                "PL-A01",
                "authentication",
                f"{mech.upper()} {result}",
                severity,
                EXPLAIN.get((mech, result), _FALLBACK).format(
                    m=mech.upper(),
                    r=result,
                    d=email.from_domain or "the sender's domain",
                ),
                evidence=f"{mech}={result}",
            )
        )
    return findings
