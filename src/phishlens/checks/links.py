"""Link analysis: where links really go, compared with what they appear to be."""

from __future__ import annotations

import ipaddress
import re

from ..domains import describe, host_of, is_punycode, lookalike_of, registrable_domain
from ..models import Email, Finding, Link, Severity
from .base import Context, check

SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly", "rebrand.ly",
    "cutt.ly", "shorturl.at", "rb.gy", "tiny.cc",
}  # fmt: skip

_LOOKS_LIKE_URL = re.compile(r"^(https?://|www\.)?([a-z0-9-]+\.)+[a-z]{2,}(/\S*)?$", re.I)


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host.strip("[]"))
        return True
    except ValueError:
        return False


@check("PL-L01", "Link text vs. destination", "links")
def mismatched_text(email: Email, ctx: Context) -> list[Finding]:
    """The classic trick: the text shows one website, the link goes to another."""
    findings = []
    for link in email.links:
        text = link.text.strip()
        if not _LOOKS_LIKE_URL.match(text):
            continue
        shown, real = host_of(text), host_of(link.href)
        if shown and real and registrable_domain(shown) != registrable_domain(real):
            findings.append(
                Finding(
                    "PL-L01",
                    "links",
                    "Link text hides a different destination",
                    Severity.HIGH,
                    f"The link says '{shown}' but actually goes to '{real}'. Hovering over a "
                    "link (or long-pressing on a phone) shows its real destination.",
                    evidence=f"text={text}  href={link.href}",
                )
            )
    return findings


@check("PL-L02", "Suspicious link destinations", "links")
def suspicious_destinations(email: Email, ctx: Context) -> list[Finding]:
    findings = []
    for link in email.links:
        host = host_of(link.href)
        if not host:
            continue
        brand = lookalike_of(host, ctx.brands)
        if brand:
            findings.append(
                _f(
                    "Link to a look-alike domain",
                    Severity.HIGH,
                    link,
                    f"{describe(host)} imitates '{brand}'. Fake login pages are hosted on "
                    "domains like this to collect passwords.",
                )
            )
        elif is_punycode(host):
            findings.append(
                _f(
                    "Link uses international characters",
                    Severity.MEDIUM,
                    link,
                    "The domain contains non-Latin characters that may imitate a familiar name.",
                )
            )
        if _is_ip(host):
            findings.append(
                _f(
                    "Link points to a raw IP address",
                    Severity.HIGH,
                    link,
                    "Legitimate organisations link to their domain name, not a "
                    "bare server address. This usually means a hastily set-up "
                    "or compromised server.",
                )
            )
        if host in SHORTENERS:
            findings.append(
                _f(
                    "Shortened link",
                    Severity.LOW,
                    link,
                    "A URL shortener hides the real destination until you click.",
                )
            )
        if "@" in link.href.split("//", 1)[-1].split("/", 1)[0]:
            findings.append(
                _f(
                    "Link contains '@' to disguise its destination",
                    Severity.HIGH,
                    link,
                    "In 'https://trusted.com@evil.example', everything "
                    "before the @ is ignored and the browser goes to "
                    "evil.example.",
                )
            )
    return findings  # fmt: skip


def _f(title: str, severity: Severity, link: Link, explanation: str) -> Finding:
    return Finding("PL-L02", "links", title, severity, explanation, evidence=link.href)
