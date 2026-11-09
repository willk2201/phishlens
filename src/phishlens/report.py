"""Output formats: terminal text, JSON and HTML.

Two safety rules apply to every format:

1. **Defang links.** A phishing report is full of malicious URLs. Each one is rewritten
   as ``hxxp://evil[.]example/login`` so it can't be clicked or auto-linked by an email
   client or chat app the report is pasted into. This is standard practice in threat
   intelligence reports.
2. **Escape everything in HTML.** The email's sender chose every subject, name and link
   in it; the HTML report escapes all of it and ships a CSP that forbids scripts.
"""

from __future__ import annotations

import json
import re
from html import escape

from . import __version__
from .models import Analysis, Severity

_URL = re.compile(r"\b(?:https?|ftp)://[^\s\"'<>]+|\bwww\.[^\s\"'<>]+", re.IGNORECASE)


def defang(text: str) -> str:
    """Make URLs unclickable: https://evil.example/x -> hxxps://evil[.]example/x"""

    def fix(m: re.Match) -> str:
        url = m.group(0)
        url = re.sub(r"^http", "hxxp", url, flags=re.IGNORECASE)
        url = re.sub(r"^ftp", "fxp", url, flags=re.IGNORECASE)
        scheme, sep, rest = url.partition("://")
        if not sep:
            scheme, rest = "", url
        host, slash, path = rest.partition("/")
        return f"{scheme}{sep}{host.replace('.', '[.]')}{slash}{path}"

    return _URL.sub(fix, text)


_ANSI = {
    Severity.HIGH: "\033[1;91m",
    Severity.MEDIUM: "\033[1;93m",
    Severity.LOW: "\033[1;96m",
    Severity.INFO: "\033[2m",
}
_VERDICT_ANSI = {"Likely phishing": "\033[1;97;41m", "Suspicious": "\033[1;30;43m",
                 "Likely safe": "\033[1;97;42m"}  # fmt: skip
_RESET, _BOLD, _DIM = "\033[0m", "\033[1m", "\033[2m"


def to_text(a: Analysis, color: bool = True) -> str:
    def c(code: str, s: str) -> str:
        return f"{code}{s}{_RESET}" if color else s

    e = a.email
    lines = [
        c(_BOLD, f"PhishLens v{__version__}  {a.source}"),
        f"  From:    {e.from_name} <{e.from_address}>"
        if e.from_name
        else f"  From:    {e.from_address}",
        f"  Subject: {e.subject}",
        "",
        f"{c(_VERDICT_ANSI[a.verdict], f' {a.verdict.upper()} ')}  risk score {a.score}/100",
        "",
    ]
    for f in a.findings:
        lines.append(
            f"{c(_ANSI[f.severity], f' {f.severity.value.upper():<6} ')} "
            f"{c(_BOLD, f.title)}  {c(_DIM, f.check_id)}"
        )
        lines.append(f"         {f.explanation}")
        if f.evidence:
            lines.append(c(_DIM, f"         Seen: {defang(f.evidence)}"))
        lines.append("")
    if not a.findings:
        lines.append("No warning signs found.\n")
    counts = ", ".join(f"{n} {s.value}" for s, n in a.by_severity.items() if n)
    lines.append(c(_BOLD, f"{len(a.findings)} warning signs" + (f": {counts}" if counts else "")))
    return "\n".join(lines)


def _analysis_dict(a: Analysis) -> dict:
    e = a.email
    return {
        "source": a.source,
        "verdict": a.verdict,
        "score": a.score,
        "email": {
            "subject": e.subject,
            "from_name": e.from_name,
            "from_address": e.from_address,
            "reply_to": e.reply_to,
            "links": [{"href": defang(x.href), "text": x.text} for x in e.links],
            "attachments": [x.filename for x in e.attachments],
        },
        "summary": {s.value: n for s, n in a.by_severity.items()},
        "findings": [{**f.to_dict(), "evidence": defang(f.evidence)} for f in a.findings],
    }


def to_json(analyses: list[Analysis]) -> str:
    return json.dumps(
        {"tool": "phishlens", "version": __version__,
         "results": [_analysis_dict(a) for a in analyses]},
        indent=2,
        ensure_ascii=False,
    )  # fmt: skip


_CSS = """
:root{--bg:#f5f6f8;--panel:#fff;--text:#15171c;--muted:#5c6370;--line:#e1e4e9;--code:#eff1f4;
--high:#c92a2a;--medium:#b7791f;--low:#1971c2;--info:#6b7280;--safe:#2b8a3e}
@media (prefers-color-scheme:dark){:root{--bg:#0f1115;--panel:#171a21;--text:#e6e8ec;
--muted:#9aa3b0;--line:#2a2f3a;--code:#1e222b;--high:#ff6b6b;--medium:#f2c94c;--low:#5aa9ff;
--info:#9aa3b0;--safe:#69db7c}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);
font:15px/1.5 system-ui,-apple-system,"Segoe UI",sans-serif}
main{max-width:960px;margin:0 auto;padding:32px 16px 64px}
h1{margin:0 0 4px;font-size:24px}.sub{color:var(--muted);margin:0 0 24px}
section.email{background:var(--panel);border:1px solid var(--line);border-radius:12px;
padding:18px;margin-bottom:24px}
.head{display:flex;flex-wrap:wrap;justify-content:space-between;gap:12px;align-items:flex-start}
.meta{font-size:14px;word-break:break-word}
.meta b{display:inline-block;width:64px;color:var(--muted);font-weight:500}
.verdict{border-radius:10px;padding:10px 14px;text-align:center;min-width:150px;color:#fff}
.verdict b{display:block;font-size:17px}.verdict span{font-size:13px;opacity:.9}
.v-phish{background:var(--high)}.v-susp{background:var(--medium);color:#15171c}
.v-safe{background:var(--safe)}
.f{border-left:4px solid currentColor;padding:8px 0 8px 12px;margin:14px 0 0}
.f h3{margin:0;font-size:15px;color:var(--text)}.f p{margin:4px 0;color:var(--text)}
.badge{font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.05em;margin-right:6px}
.high{color:var(--high)}.medium{color:var(--medium)}.low{color:var(--low)}.info{color:var(--info)}
code{background:var(--code);padding:2px 6px;border-radius:5px;font-size:12.5px;word-break:break-all;
color:var(--text)}
.none{color:var(--safe);margin-top:12px}
"""

_VCLASS = {
    "Likely phishing": "v-phish",
    "Suspicious": "v-susp",
    "Likely safe": "v-safe",
}


def to_html(analyses: list[Analysis]) -> str:
    e = escape
    sections = []
    for a in analyses:
        m = a.email
        sender = (
            f"{e(m.from_name)} &lt;{e(m.from_address)}&gt;" if m.from_name else e(m.from_address)
        )
        items = "".join(
            f'<div class="f {f.severity.value}"><h3><span class="badge">{f.severity.value}'
            f"</span>{e(f.title)}</h3><p>{e(f.explanation)}</p>"
            + (f"<p>Seen: <code>{e(defang(f.evidence))}</code></p>" if f.evidence else "")
            + "</div>"
            for f in a.findings
        )
        sections.append(
            f'<section class="email"><div class="head"><div class="meta">'
            f"<div><b>File</b>{e(a.source)}</div><div><b>From</b>{sender}</div>"
            f"<div><b>Subject</b>{e(m.subject)}</div></div>"
            f'<div class="verdict {_VCLASS[a.verdict]}"><b>{e(a.verdict)}</b>'
            f"<span>risk {a.score}/100</span></div></div>"
            f"{items or '<p class=none>No warning signs found.</p>'}</section>"
        )
    count = len(analyses)
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'">
<title>PhishLens Report</title><style>{_CSS}</style></head>
<body><main>
<h1>PhishLens Report</h1>
<p class="sub">{count} email{"s" if count != 1 else ""} analysed · v{__version__} ·
links are defanged (hxxp, [.]) so they can't be clicked</p>
{"".join(sections)}
</main></body></html>
"""
