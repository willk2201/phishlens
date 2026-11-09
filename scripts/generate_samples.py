"""Generate the sample emails in samples/.

Every organisation, person and domain is fictional. Domains use the reserved
``.example`` TLD (RFC 2606) and IPs come from documentation ranges (RFC 5737), so
nothing here points at a real website or impersonates a real company. Attachments
are harmless placeholder text with suspicious *names*, which is all PhishLens inspects.

    python scripts/generate_samples.py
"""

from __future__ import annotations

import zlib
from email.message import EmailMessage
from email.utils import formataddr
from pathlib import Path

OUT = Path(__file__).resolve().parent.parent / "samples"
BANK = "northwind-bank.example"
# "nоrthwind-bank" with a Cyrillic "о", written in punycode as real mail would carry it.
HOMOGRAPH = "nоrthwind-bank".encode("idna").decode("ascii") + ".example"


def message(
    *,
    subject: str,
    from_name: str,
    from_addr: str,
    auth: str,
    html: str | None = None,
    text: str | None = None,
    reply_to: str | None = None,
    to: str = "alex.taylor@fernhill.example",
    day: int = 3,
) -> EmailMessage:
    msg = EmailMessage()
    msg["Authentication-Results"] = f"mx.fernhill.example; {auth}"
    msg["Return-Path"] = f"<{from_addr}>"
    msg["From"] = formataddr((from_name, from_addr))
    msg["To"] = to
    if reply_to:
        msg["Reply-To"] = reply_to
    msg["Subject"] = subject
    msg["Date"] = f"Tue, 0{day} Nov 2026 09:14:00 +0000"
    msg["Message-ID"] = f"<sample-{zlib.crc32(subject.encode())}@phishlens.example>"
    if text:
        msg.set_content(text)
    if html:
        if text:
            msg.add_alternative(html, subtype="html")
        else:
            msg.set_content(html, subtype="html")
    return msg


def samples() -> dict[str, EmailMessage]:
    out: dict[str, EmailMessage] = {}

    out["01_legitimate_newsletter.eml"] = message(
        subject="Your November savings update",
        from_name="Northwind Bank",
        from_addr=f"news@{BANK}",
        auth="spf=pass smtp.mailfrom=northwind-bank.example; dkim=pass "
        "header.d=northwind-bank.example; dmarc=pass header.from=northwind-bank.example",
        text="Hello Alex,\n\nYour savings rate is changing next month. You can read the "
        f"details at https://www.{BANK}/savings or in the app.\n\nNorthwind Bank",
        html=f"""<p>Hello Alex,</p>
<p>Your savings rate is changing next month. You can read the details on our
<a href="https://www.{BANK}/savings">savings page</a> or in the app.</p>
<p><a href="https://www.{BANK}/savings">https://www.{BANK}/savings</a></p>
<p>Northwind Bank</p>""",
    )

    out["02_account_suspended.eml"] = message(
        subject="URGENT: Your account has been suspended",
        from_name="Northwind Bank Security",
        from_addr="security@n0rthwind-bank.example",
        reply_to="northwind.help@freemail.example",
        auth="spf=fail smtp.mailfrom=n0rthwind-bank.example; dkim=none; "
        "dmarc=fail header.from=n0rthwind-bank.example",
        html=f"""<p>Dear Customer,</p>
<p>We detected unusual sign-in activity. Your account has been suspended to protect you.</p>
<p>To restore access you must verify your identity within 24 hours, or your account will be
closed permanently.</p>
<p><a href="http://203.0.113.50/northwind/login.php">https://www.{BANK}/secure</a></p>
<p>Or sign in here: <a href="https://{BANK}.account-verify.example/login">Restore access</a></p>
<p>Northwind Bank Security Team</p>""",
    )

    invoice = message(
        subject="Final notice: overdue invoice INV-20931",
        from_name="Accounts Payable",
        from_addr="billing@fastpay-invoices.example",
        auth="spf=softfail smtp.mailfrom=fastpay-invoices.example; dkim=pass "
        "header.d=fastpay-invoices.example; dmarc=none",
        text="Hello,\n\nThis is a final notice regarding invoice INV-20931, which is now 30 "
        "days overdue. Please review the attached invoice and remittance form immediately "
        "to avoid legal action.\n\nAccounts Payable",
    )
    placeholder = b"Harmless placeholder used to test PhishLens. Not a real program.\n"
    invoice.add_attachment(
        placeholder, maintype="application", subtype="octet-stream",
        filename="Invoice_INV-20931.pdf.exe",
    )  # fmt: skip
    invoice.add_attachment(
        b"<html><body><p>Placeholder page for PhishLens tests.</p></body></html>",
        maintype="text", subtype="html", filename="Remittance_Form.html",
    )  # fmt: skip
    out["03_invoice_attachment.eml"] = invoice

    out["04_ceo_gift_cards.eml"] = message(
        subject="Quick favour",
        from_name="Sarah Mitchell (CEO)",
        from_addr="s.mitchell.ceo@freemail.example",
        # The free webmail provider really did send it, so authentication passes.
        # Passing SPF/DKIM/DMARC proves who *sent* it, not that they are who they claim.
        auth="spf=pass smtp.mailfrom=freemail.example; dkim=pass header.d=freemail.example; "
        "dmarc=pass header.from=freemail.example",
        text="Hi Alex,\n\nAre you at your desk? I'm in a meeting all afternoon and need a "
        "quick favour. I need you to buy six £100 gift cards for a client today, urgently. "
        "I'll reimburse you this evening.\n\nPlease keep this between us for now, it's a "
        "surprise. Send me the codes by email when you have them.\n\nSarah\nSent from my "
        "phone",
    )

    out["05_homograph_link.eml"] = message(
        subject="Action required: confirm your payment details",
        from_name="Northwind Bank",
        from_addr=f"alerts@{HOMOGRAPH}",
        auth=f"spf=pass smtp.mailfrom={HOMOGRAPH}; dkim=pass header.d={HOMOGRAPH}; dmarc=pass",
        html=f"""<p>Hello,</p>
<p>A recent payment could not be processed. Please confirm your payment details to avoid
interruption to your service.</p>
<p><a href="https://{BANK}@198.51.100.7/confirm">Confirm payment details</a></p>
<p><a href="https://{HOMOGRAPH}/billing">View your account</a></p>""",
    )
    return out


def main() -> None:
    OUT.mkdir(exist_ok=True)
    for name, msg in samples().items():
        (OUT / name).write_bytes(bytes(msg))
    (OUT / "brands.txt").write_text(
        "# Extra domains to protect, one per line (added to the built-in list).\n"
        "# The samples impersonate this fictional bank:\n"
        f"{BANK}\n",
        encoding="utf-8",
    )
    print(f"Wrote {len(samples())} sample emails to {OUT}")


if __name__ == "__main__":
    main()
