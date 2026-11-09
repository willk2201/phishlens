import json

import pytest

from phishlens.cli import main
from phishlens.engine import analyse_file
from phishlens.parse import parse_bytes, parse_file
from phishlens.report import defang, to_html

EXPECTED = {
    "01_legitimate_newsletter.eml": "Likely safe",
    "02_account_suspended.eml": "Likely phishing",
    "03_invoice_attachment.eml": "Likely phishing",
    "04_ceo_gift_cards.eml": "Likely phishing",
    "05_homograph_link.eml": "Likely phishing",
}


# --------------------------------------------------------------------------- parsing
def test_parse_extracts_sender_links_and_attachments(samples):
    e = parse_file(samples / "02_account_suspended.eml")
    assert e.from_name == "Northwind Bank Security"
    assert e.from_address == "security@n0rthwind-bank.example"
    assert e.reply_to == "northwind.help@freemail.example"
    assert "dmarc=fail" in e.auth_results
    assert any(x.href.startswith("http://203.0.113.50") for x in e.links)
    assert "unusual sign-in" in e.text

    inv = parse_file(samples / "03_invoice_attachment.eml")
    assert [a.filename for a in inv.attachments] == [
        "Invoice_INV-20931.pdf.exe",
        "Remittance_Form.html",
    ]


def test_parse_plain_text_bare_urls():
    raw = (
        b"From: a@b.example\r\nSubject: hi\r\n\r\nGo to https://x.example/a, or www.y.example.\r\n"
    )
    e = parse_bytes(raw)
    assert [x.href for x in e.links] == ["https://x.example/a", "www.y.example"]


def test_parse_html_ignores_scripts_and_mailto():
    raw = (
        b"From: a@b.example\r\nContent-Type: text/html\r\n\r\n"
        b"<script>var u='https://hidden.example'</script><a href='mailto:x@y.example'>mail</a>"
        b"<a href='https://ok.example'>  Visit   us </a>"
    )
    e = parse_bytes(raw)
    assert [(x.href, x.text) for x in e.links] == [("https://ok.example", "Visit us")]
    assert "hidden.example" not in e.text


def test_parse_survives_garbage():
    e = parse_bytes(b"\x00\xff not an email at all")
    assert e.from_address == "" and e.links == []
    e = parse_bytes(b"From: <<<@@@>>>\r\nContent-Type: text/plain; charset=nope\r\n\r\n\xff\xfe")
    assert isinstance(e.text, str)


def test_topmost_authentication_header_wins():
    raw = (
        b"Authentication-Results: mx.mine; dmarc=fail\r\n"
        b"Authentication-Results: forged; dmarc=pass\r\n"
        b"From: a@b.example\r\n\r\nhi"
    )
    assert "dmarc=fail" in parse_bytes(raw).auth_results


# --------------------------------------------------------------------------- reports
@pytest.mark.parametrize(
    "raw, safe",
    [
        ("http://evil.example/login", "hxxp://evil[.]example/login"),
        ("https://a.b.example/x.php?y=1.2", "hxxps://a[.]b[.]example/x.php?y=1.2"),
        ("see www.evil.example now", "see www[.]evil[.]example now"),
        ("no links here.", "no links here."),
    ],
)
def test_defang(raw, safe):
    assert defang(raw) == safe


def test_html_report_escapes_and_defangs(samples):
    a = analyse_file(samples / "02_account_suspended.eml")
    a.email.subject = '<script>alert("x")</script>'
    html = to_html([a])
    assert "<script>alert" not in html and "&lt;script&gt;" in html
    assert "http://203.0.113.50" not in html and "hxxp://203[.]0[.]113[.]50" in html


# ------------------------------------------------------------------------ end to end
def test_all_samples_get_expected_verdicts(samples, tmp_path, capsys):
    out = tmp_path / "r.json"
    files = [str(samples / name) for name in EXPECTED]
    code = main(["analyse", *files, "--brands", str(samples / "brands.txt"),
                 "--json", str(out), "--html", str(tmp_path / "r.html"), "--no-color"])  # fmt: skip
    assert code == 0
    results = json.loads(out.read_text())["results"]
    assert {r["source"].rsplit("/", 1)[-1]: r["verdict"] for r in results} == EXPECTED
    assert "LIKELY PHISHING" in capsys.readouterr().out


def test_without_brand_list_lookalikes_of_fictional_bank_are_missed(samples):
    """Documents a real limitation: look-alike detection only knows the brands it's given."""
    a = analyse_file(samples / "02_account_suspended.eml")
    assert not any(f.check_id == "PL-S01" for f in a.findings)
    assert a.verdict == "Likely phishing"  # other signs still catch it


def test_fail_on(samples):
    legit = str(samples / "01_legitimate_newsletter.eml")
    phish = str(samples / "04_ceo_gift_cards.eml")
    assert main(["analyse", legit, "-q", "--fail-on", "suspicious"]) == 0
    assert main(["analyse", phish, "-q", "--fail-on", "phishing"]) == 1


def test_cli_errors(tmp_path, capsys):
    assert main(["analyse", str(tmp_path / "missing.eml")]) == 2
    eml = tmp_path / "a.eml"
    eml.write_bytes(b"From: a@b.example\r\n\r\nhi")
    assert main(["analyse", str(eml), "--brands", str(tmp_path / "nope.txt")]) == 2
    assert "error" in capsys.readouterr().err


def test_checks_command(capsys):
    assert main(["checks"]) == 0
    assert "PL-L01" in capsys.readouterr().out
