import pytest

from phishlens.domains import (
    DEFAULT_BRANDS,
    decode_idn,
    edit_distance,
    host_of,
    lookalike_of,
    registrable_domain,
    skeleton,
)

BRANDS = (*DEFAULT_BRANDS, "northwind-bank.example")


@pytest.mark.parametrize(
    "host, expected",
    [
        ("mail.paypal.com", "paypal.com"),
        ("www.amazon.co.uk", "amazon.co.uk"),
        ("hmrc.gov.uk", "hmrc.gov.uk"),
        ("a.b.c.example", "c.example"),
        ("PayPal.COM.", "paypal.com"),
    ],
)
def test_registrable_domain(host, expected):
    assert registrable_domain(host) == expected


def test_host_of_handles_www_and_garbage():
    assert host_of("www.example.com/x") == "www.example.com"
    assert host_of("https://User@Host.Example:8443/p") == "host.example"
    assert host_of("http://[::1") == ""  # malformed IPv6 must not crash


def test_edit_distance():
    assert edit_distance("kitten", "sitting") == 3
    assert edit_distance("paypal", "paypal") == 0
    assert edit_distance("", "abc") == 3


def test_skeleton_collapses_confusables():
    assert skeleton("paypa1") == skeleton("paypal")
    assert skeleton("rnicrosoft") == skeleton("microsoft")
    assert skeleton("аpple") == skeleton("apple")  # Cyrillic а


def test_decode_idn():
    assert decode_idn("xn--pple-43d.com") == "аpple.com"
    assert decode_idn("xn--zz.com") == "xn--zz.com"  # invalid punycode left alone


@pytest.mark.parametrize(
    "host, brand",
    [
        ("paypa1.com", "paypal.com"),  # digit swap
        ("rnicrosoft.com", "microsoft.com"),  # rn -> m
        ("gooogle.com", "google.com"),  # extra letter
        ("amaz0n.co.uk", "amazon.co.uk"),  # prefers the same suffix
        ("paypal.com.account-check.example", "paypal.com"),  # brand as subdomain
        ("xn--pple-43d.com", "apple.com"),  # Cyrillic а homograph
        ("xn--80ak6aa92e.com", "apple.com"),  # all-Cyrillic "аррӏе"
        ("n0rthwind-bank.example", "northwind-bank.example"),
        ("northwindbank.example", "northwind-bank.example"),  # hyphen removed
    ],
)
def test_lookalikes_detected(host, brand):
    assert lookalike_of(host, BRANDS) == brand


@pytest.mark.parametrize(
    "host",
    [
        "www.paypal.com",
        "mail.google.com",
        "apple.com",
        "hmrc.gov.uk",
        "bbc.co.uk",
        "login.microsoftonline.com",  # real Microsoft domain, not in the list: unrelated
        "github.com",
        "",
    ],
)
def test_real_and_unrelated_domains_not_flagged(host):
    assert lookalike_of(host, BRANDS) is None
