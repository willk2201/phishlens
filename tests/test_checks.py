import pytest
from conftest import BANK, CTX, attachment, link, make_email

from phishlens.checks import attachments, auth, content, links, sender
from phishlens.engine import analyse
from phishlens.models import Severity


def titles(findings):
    return [f.title for f in findings]


def test_clean_email_has_no_findings():
    a = analyse(make_email(), CTX)
    assert a.findings == [] and a.score == 0 and a.verdict == "Likely safe"


# ------------------------------------------------------------------- authentication
def test_parse_auth_results_first_wins():
    assert auth.parse_auth_results("spf=pass a; dkim=fail; dmarc=fail; spf=fail") == {
        "spf": "pass",
        "dkim": "fail",
        "dmarc": "fail",
    }


@pytest.mark.parametrize(
    "header, expected",
    [
        ("spf=pass; dkim=pass; dmarc=fail", [("DMARC fail", Severity.HIGH)]),
        ("spf=fail; dkim=pass; dmarc=pass", [("SPF fail", Severity.MEDIUM)]),
        ("spf=softfail; dkim=none; dmarc=none", [("DMARC none", Severity.LOW),
                                                 ("SPF softfail", Severity.LOW),
                                                 ("DKIM none", Severity.LOW)]),
        ("SPF=Pass; DKIM=Pass; DMARC=Pass", []),
    ],
)  # fmt: skip
def test_authentication(header, expected):
    found = auth.authentication(make_email(auth_results=header), CTX)
    assert [(f.title, f.severity) for f in found] == expected


def test_missing_auth_header_is_info_only():
    (f,) = auth.authentication(make_email(auth_results=None), CTX)
    assert f.severity is Severity.INFO


def test_unknown_auth_result_uses_fallback_text():
    (f,) = auth.authentication(make_email(auth_results="dkim=neutral"), CTX)
    assert "neutral" in f.explanation


# -------------------------------------------------------------------------- sender
def test_lookalike_sender():
    found = sender.lookalike_sender(make_email(from_address="x@n0rthwind-bank.example"), CTX)
    assert titles(found) == [f"Sender domain imitates {BANK}"]


def test_punycode_sender_shows_what_victim_sees():
    found = sender.lookalike_sender(make_email(from_address="a@xn--pple-43d.com"), CTX)
    assert {f.severity for f in found} == {Severity.HIGH, Severity.MEDIUM}
    assert any("displayed as 'аpple.com'" in f.explanation for f in found)


def test_display_name_claims_brand():
    e = make_email(from_name="PayPal Support", from_address="help@random-host.example")
    (f,) = sender.display_name(e, CTX)
    assert f.title == "Display name claims to be Paypal" and f.severity is Severity.HIGH


def test_display_name_brand_on_real_domain_is_fine():
    assert (
        sender.display_name(make_email(from_name="PayPal", from_address="a@paypal.com"), CTX) == []
    )


def test_display_name_contains_other_address():
    e = make_email(from_name="billing@paypal.com", from_address="x@evil.example")
    assert "Display name contains a different email address" in titles(sender.display_name(e, CTX))


def test_official_name_on_free_webmail():
    e = make_email(from_name="Finance Director", from_address="fd.office@gmail.com")
    assert titles(sender.display_name(e, CTX)) == ["Official-sounding sender using free webmail"]
    e = make_email(from_name="Jamie Lee", from_address="jamie@gmail.com")  # ordinary person
    assert sender.display_name(e, CTX) == []


@pytest.mark.parametrize(
    "reply_to, severity",
    [
        (None, None),
        (f"support@{BANK}", None),
        (f"support@help.{BANK}", None),  # same organisation, different subdomain
        ("collect@other-company.example", Severity.MEDIUM),
        ("scammer@gmail.com", Severity.HIGH),
    ],
)
def test_reply_to(reply_to, severity):
    found = sender.reply_to(make_email(reply_to=reply_to), CTX)
    assert (found[0].severity if found else None) is severity


# --------------------------------------------------------------------------- links
def test_link_text_hides_destination():
    e = make_email(links=[link("http://203.0.113.9/login", f"https://www.{BANK}/secure")])
    (f,) = links.mismatched_text(e, CTX)
    assert "203.0.113.9" in f.explanation


@pytest.mark.parametrize(
    "text", ["Click here", f"https://{BANK}/account", f"www.{BANK}", "Sign in"]
)
def test_honest_link_text_not_flagged(text):
    e = make_email(links=[link(f"https://www.{BANK}/account", text)])
    assert links.mismatched_text(e, CTX) == []


@pytest.mark.parametrize(
    "href, title",
    [
        ("http://198.51.100.4/x", "Link points to a raw IP address"),
        ("http://[2001:db8::1]/x", "Link points to a raw IP address"),
        ("https://bit.ly/abc", "Shortened link"),
        ("https://paypa1.com/login", "Link to a look-alike domain"),
        (f"https://{BANK}@evil.example/x", "Link contains '@' to disguise its destination"),
        ("https://xn--caf-dma.example/", "Link uses international characters"),
    ],
)
def test_suspicious_destinations(href, title):
    assert title in titles(links.suspicious_destinations(make_email(links=[link(href)]), CTX))


def test_normal_link_not_flagged():
    e = make_email(links=[link(f"https://www.{BANK}/savings?x=1")])
    assert links.suspicious_destinations(e, CTX) == []


# ------------------------------------------------------------------------- content
@pytest.mark.parametrize(
    "text, title",
    [
        ("Your account will be suspended within 24 hours", "Urgent or threatening language"),
        ("Please verify your password here", "Asks for passwords or personal details"),
        ("Can you buy some gift cards for me?", "Unusual payment request"),
        ("Our new bank details are below", "Unusual payment request"),
        ("Keep this between us please", "Asks you to keep it secret"),
        ("Dear Customer, hello", "Generic greeting"),
    ],
)
def test_language_patterns(text, title):
    assert title in titles(content.language(make_email(text=text), CTX))


def test_subject_is_also_scanned():
    found = content.language(make_email(subject="FINAL NOTICE", text="hi"), CTX)
    assert titles(found) == ["Urgent or threatening language"]


def test_ordinary_text_not_flagged():
    text = "Hi Alex, attached are the minutes from Tuesday. See you at training on Friday."
    assert content.language(make_email(text=text), CTX) == []


# --------------------------------------------------------------------- attachments
@pytest.mark.parametrize(
    "name, title, severity",
    [
        ("invoice.pdf.exe", "Disguised file extension", Severity.HIGH),
        ("scan.jpg.html", "Disguised file extension", Severity.HIGH),
        ("setup.EXE", "Executable attachment", Severity.HIGH),
        ("update.js", "Executable attachment", Severity.HIGH),
        ("budget.xlsm", "Macro-enabled Office document", Severity.MEDIUM),
        ("login.html", "HTML attachment", Severity.MEDIUM),
        ("files.iso", "Archive or disk-image attachment", Severity.LOW),
    ],
)
def test_risky_attachments(name, title, severity):
    (f,) = attachments.risky_attachments(make_email(attachments=[attachment(name)]), CTX)
    assert (f.title, f.severity) == (title, severity)


@pytest.mark.parametrize("name", ["report.pdf", "photo.v2.final.jpg", "notes.docx", "noext"])
def test_safe_attachments(name):
    assert attachments.risky_attachments(make_email(attachments=[attachment(name)]), CTX) == []


# ------------------------------------------------------------------------- scoring
def test_wording_alone_stays_below_phishing():
    """Pressure language is weak evidence: a real (if pushy) email shouldn't be 'phishing'."""
    e = make_email(text="Final reminder: your subscription expires today, act now!")
    assert analyse(e, CTX).verdict != "Likely phishing"


def test_score_caps_at_100_and_findings_sorted():
    e = make_email(
        from_address="a@paypa1.com",
        from_name="PayPal",
        auth_results="dmarc=fail; spf=fail",
        links=[link("http://198.51.100.1/x", "https://paypal.com")],
        attachments=[attachment("invoice.pdf.exe")],
    )
    a = analyse(e, CTX)
    assert a.score == 100 and a.verdict == "Likely phishing"
    ranks = [f.severity.rank for f in a.findings]
    assert ranks == sorted(ranks, reverse=True)
