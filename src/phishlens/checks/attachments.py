"""Attachment checks, using only the file name and type.

PhishLens never opens, extracts or runs attachments: that is the job of a sandbox
or antivirus engine, and doing it here would put the analyst's machine at risk.
"""

from __future__ import annotations

from pathlib import PurePosixPath

from ..models import Email, Finding, Severity
from .base import Context, check

# Files that run code when opened (or commonly lead to it).
EXECUTABLE = {
    ".exe", ".scr", ".com", ".bat", ".cmd", ".pif", ".msi", ".js", ".jse", ".vbs", ".vbe",
    ".wsf", ".hta", ".ps1", ".jar", ".lnk", ".reg", ".cpl",
}  # fmt: skip
# Containers often used to sneak executables past email filters.
CONTAINERS = {".iso", ".img", ".vhd", ".zip", ".rar", ".7z", ".ace", ".cab"}
# Office files with macros enabled.
MACRO = {".docm", ".xlsm", ".pptm", ".dotm", ".xltm"}
# HTML attachments open a local page, often a fake login form that bypasses link scanners.
HTML = {".html", ".htm", ".shtml", ".svg"}
DOCUMENT = {".pdf", ".doc", ".docx", ".xls", ".xlsx", ".txt", ".jpg", ".png", ".csv"}


@check("PL-F01", "Dangerous attachments", "attachments")
def risky_attachments(email: Email, ctx: Context) -> list[Finding]:
    findings = []
    for att in email.attachments:
        name = att.filename.strip().lower()
        suffixes = [s for s in PurePosixPath(name).suffixes if len(s) <= 6]
        ext = suffixes[-1] if suffixes else ""

        if len(suffixes) >= 2 and suffixes[-2] in DOCUMENT and ext in EXECUTABLE | HTML:
            findings.append(
                _f(
                    att.filename,
                    "Disguised file extension",
                    Severity.HIGH,
                    f"'{att.filename}' pretends to be a {suffixes[-2]} file but is "
                    f"really {ext}. Windows hides known extensions by default, so "
                    f"it shows as '{att.filename.rsplit('.', 1)[0]}'.",
                )
            )
        elif ext in EXECUTABLE:
            findings.append(
                _f(
                    att.filename,
                    "Executable attachment",
                    Severity.HIGH,
                    f"{ext} files run code as soon as they're opened. There is "
                    "almost never a legitimate reason to email one.",
                )
            )
        elif ext in MACRO:
            findings.append(
                _f(
                    att.filename,
                    "Macro-enabled Office document",
                    Severity.MEDIUM,
                    "Macros can run code when you click 'Enable Content'; this is "
                    "a long-standing malware delivery route.",
                )
            )
        elif ext in HTML:
            findings.append(
                _f(
                    att.filename,
                    "HTML attachment",
                    Severity.MEDIUM,
                    "An attached web page opens locally in your browser, often as a "
                    "fake sign-in form, and avoids the scanners that check links.",
                )
            )
        elif ext in CONTAINERS:
            findings.append(
                _f(
                    att.filename,
                    "Archive or disk-image attachment",
                    Severity.LOW,
                    "Archives and disk images can hide executables from email "
                    "filters. Treat with care if unexpected.",
                )
            )
    return findings  # fmt: skip


def _f(filename: str, title: str, severity: Severity, why: str) -> Finding:
    return Finding("PL-F01", "attachments", title, severity, why, evidence=filename)
