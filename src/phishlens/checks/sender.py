"""Who the email claims to be from, versus who it is really from."""

from __future__ import annotations

import re

from ..domains import (
    brand_label,
    describe,
    is_punycode,
    lookalike_of,
    registrable_domain,
)
from ..models import Email, Finding, Severity
from .base import Context, check

FREE_MAIL = {
    "gmail.com", "googlemail.com", "outlook.com", "hotmail.com", "hotmail.co.uk", "live.com",
    "yahoo.com", "yahoo.co.uk", "aol.com", "icloud.com", "proton.me", "protonmail.com",
    "gmx.com", "mail.com", "freemail.example",
}  # fmt: skip

# Display names that suggest an organisation or authority rather than a person.
_ORG_WORDS = re.compile(
    r"\b(bank|security|support|service|team|account|admin|it desk|helpdesk|billing|"
    r"payroll|hr|ceo|director|finance|delivery|courier|hmrc|tax|refund)\b",
    re.IGNORECASE,
)
_EMAIL_IN_NAME = re.compile(r"[\w.+-]+@([\w-]+\.)+[\w-]+")


@check("PL-S01", "Look-alike sender domain", "sender")
def lookalike_sender(email: Email, ctx: Context) -> list[Finding]:
    findings = []
    brand = lookalike_of(email.from_domain, ctx.brands)
    if brand:
        findings.append(
            Finding(
                "PL-S01",
                "sender",
                f"Sender domain imitates {brand}",
                Severity.HIGH,
                f"The email comes from {describe(email.from_domain)}, which is designed to "
                f"look like '{brand}' at a glance (swapped or extra characters, or the real "
                "name used as part of a different domain).",
                evidence=email.from_address,
            )
        )
    if is_punycode(email.from_domain):
        findings.append(
            Finding(
                "PL-S01",
                "sender",
                "Sender domain uses international characters",
                Severity.MEDIUM,
                f"The domain {describe(email.from_domain)} is written in punycode (xn--), "
                "meaning it contains non-Latin characters that can look identical to normal "
                "letters.",
                evidence=email.from_domain,
            )
        )
    return findings


@check("PL-S02", "Display name mismatch", "sender")
def display_name(email: Email, ctx: Context) -> list[Finding]:
    name = email.from_name
    if not name:
        return []
    findings = []

    # "PayPal Support <x@random.example>": a brand in the name, but not the brand's domain.
    for brand in ctx.brands:
        brand_name = brand.split(".")[0]
        if (
            len(brand_name) >= 4
            and brand_name.replace("-", "") in name.lower().replace(" ", "").replace("-", "")
            and registrable_domain(email.from_domain) != brand
        ):
            findings.append(
                Finding(
                    "PL-S02",
                    "sender",
                    f"Display name claims to be {brand_label(brand)}",
                    Severity.HIGH,
                    f"The name shown is '{name}', but the real address is "
                    f"'{email.from_address}', which does not belong to {brand}. Most email "
                    "apps show only the name, hiding the real address.",
                    evidence=f"{name} <{email.from_address}>",
                )
            )
            break

    # "billing@bank.example <attacker@evil.example>": an address inside the name.
    m = _EMAIL_IN_NAME.search(name)
    if m and m.group(0).lower() != email.from_address:
        findings.append(
            Finding(
                "PL-S02",
                "sender",
                "Display name contains a different email address",
                Severity.HIGH,
                f"The name shows '{m.group(0)}' but the email really came from "
                f"'{email.from_address}'. This trick works because many apps show only "
                "the name.",
                evidence=f"{name} <{email.from_address}>",
            )
        )

    # "Finance Director <someone@gmail.com>": an official-sounding name on free webmail.
    if not findings and email.from_domain in FREE_MAIL and _ORG_WORDS.search(name):
        findings.append(
            Finding(
                "PL-S02",
                "sender",
                "Official-sounding sender using free webmail",
                Severity.MEDIUM,
                f"'{name}' sounds like an organisation or senior role, but the email was "
                f"sent from a free {email.from_domain} account. Organisations email from "
                "their own domain; this pattern is typical of CEO fraud.",
                evidence=f"{name} <{email.from_address}>",
            )
        )
    return findings


@check("PL-S03", "Reply-To redirection", "sender")
def reply_to(email: Email, ctx: Context) -> list[Finding]:
    if not email.reply_to or not email.from_address:
        return []
    reply_domain = email.reply_to.rpartition("@")[2]
    if registrable_domain(reply_domain) == registrable_domain(email.from_domain):
        return []
    severity = Severity.HIGH if reply_domain in FREE_MAIL else Severity.MEDIUM
    return [
        Finding(
            "PL-S03",
            "sender",
            "Replies go to a different domain",
            severity,
            f"The email is from '{email.from_domain}', but pressing Reply sends your answer "
            f"to '{email.reply_to}'. Scammers do this so the conversation reaches them, not "
            "the real organisation.",
            evidence=f"Reply-To: {email.reply_to}",
        )
    ]
