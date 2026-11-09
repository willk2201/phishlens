"""Turn a raw .eml file into an :class:`Email`.

Emails are attacker-controlled input, so parsing is defensive: undecodable bytes are
replaced, malformed headers fall back to empty values, and attachment *contents* are
never executed or written to disk (only their names, types and sizes are recorded).
"""

from __future__ import annotations

import re
from email import policy
from email.message import EmailMessage
from email.parser import BytesParser
from email.utils import getaddresses, parseaddr
from html.parser import HTMLParser
from pathlib import Path

from .models import Attachment, Email, Link

_BARE_URL = re.compile(r"""\b(?:https?://|www\.)[^\s<>"')\]]+""", re.IGNORECASE)


class _LinkExtractor(HTMLParser):
    """Collect <a href> links with their visible text, plus the page's plain text."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.links: list[Link] = []
        self.text_parts: list[str] = []
        self._href: str | None = None
        self._anchor_text: list[str] = []
        self._skip = 0  # inside <script>/<style>

    def handle_starttag(self, tag, attrs):
        if tag in ("script", "style"):
            self._skip += 1
        elif tag == "a":
            self._href = dict(attrs).get("href") or ""
            self._anchor_text = []
        elif tag in ("br", "p", "div", "tr", "li"):
            self.text_parts.append("\n")

    def handle_endtag(self, tag):
        if tag in ("script", "style") and self._skip:
            self._skip -= 1
        elif tag == "a" and self._href is not None:
            text = " ".join("".join(self._anchor_text).split())
            if self._href and not self._href.lower().startswith(("mailto:", "#", "tel:")):
                self.links.append(Link(self._href.strip(), text))
            self._href = None

    def handle_data(self, data):
        if self._skip:
            return
        self.text_parts.append(data)
        if self._href is not None:
            self._anchor_text.append(data)


def parse_bytes(raw: bytes) -> Email:
    msg: EmailMessage = BytesParser(policy=policy.default).parsebytes(raw)

    from_name, from_address = _address(msg, "From")
    _, reply_to = _address(msg, "Reply-To")
    return_path = parseaddr(str(msg.get("Return-Path", "")))[1] or None

    text_parts: list[str] = []
    links: list[Link] = []
    attachments: list[Attachment] = []

    for part in msg.walk():
        if part.is_multipart():
            continue
        disposition = part.get_content_disposition()
        filename = part.get_filename()
        if disposition == "attachment" or (filename and disposition != "inline"):
            payload = part.get_payload(decode=True) or b""
            attachments.append(
                Attachment(filename or "(unnamed)", part.get_content_type(), len(payload))
            )
            continue

        content_type = part.get_content_type()
        if content_type not in ("text/plain", "text/html"):
            continue
        try:
            body = part.get_content()
        except (LookupError, ValueError):  # unknown charset or broken encoding
            body = (part.get_payload(decode=True) or b"").decode("utf-8", "replace")

        if content_type == "text/html":
            extractor = _LinkExtractor()
            extractor.feed(body)
            links.extend(extractor.links)
            text_parts.append("".join(extractor.text_parts))
        else:
            text_parts.append(body)
            links.extend(Link(m.group(0).rstrip(".,;:"), "") for m in _BARE_URL.finditer(body))

    return Email(
        subject=str(msg.get("Subject", "")),
        from_name=from_name,
        from_address=from_address,
        reply_to=reply_to or None,
        return_path=return_path,
        auth_results=_first_header(msg, "Authentication-Results"),
        text="\n".join(text_parts),
        links=_dedupe(links),
        attachments=attachments,
    )


def parse_file(path: str | Path) -> Email:
    return parse_bytes(Path(path).read_bytes())


def _address(msg: EmailMessage, header: str) -> tuple[str, str]:
    try:
        value = msg.get(header)
        if value is None:
            return "", ""
        pairs = getaddresses([str(value)])
    except (ValueError, IndexError, TypeError):
        return "", ""
    name, address = pairs[0] if pairs else ("", "")
    return name.strip(), address.strip().lower()


def _first_header(msg: EmailMessage, name: str) -> str | None:
    """The topmost header of this name: the one added by *your own* mail server.

    Lower copies may have been inserted by the sender and can't be trusted.
    """
    values = msg.get_all(name) or []
    return str(values[0]) if values else None


def _dedupe(links: list[Link]) -> list[Link]:
    seen, out = set(), []
    for link in links:
        if (link.href, link.text) not in seen:
            seen.add((link.href, link.text))
            out.append(link)
    return out
