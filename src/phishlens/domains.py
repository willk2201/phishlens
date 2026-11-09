"""Domain analysis: finding look-alike ("typosquatted") domains.

Attackers register domains that look like a trusted brand at a glance:

* character swaps:  paypa1.com, rnicrosoft.com ("rn" looks like "m")
* small typos:      amaz0n.co.uk, gooogle.com
* brand as a subdomain:  paypal.com.account-check.example
* Unicode look-alikes (IDN homographs): "аpple.com" with a Cyrillic "а", which
  appears in raw form as punycode "xn--pple-43d.com"
"""

from __future__ import annotations

from urllib.parse import urlsplit

# Well-known, frequently impersonated brands. Extend with --brands for your organisation.
DEFAULT_BRANDS = (
    "paypal.com",
    "microsoft.com",
    "office.com",
    "apple.com",
    "icloud.com",
    "amazon.com",
    "amazon.co.uk",
    "google.com",
    "netflix.com",
    "linkedin.com",
    "dhl.com",
    "royalmail.com",
    "gov.uk",
    "hsbc.co.uk",
    "barclays.co.uk",
    "natwest.com",
    "lloydsbank.com",
    "docusign.com",
    "dropbox.com",
    "ed.ac.uk",
)

# Second-level labels used under country-code TLDs, e.g. the "co" in example.co.uk.
_SECOND_LEVEL = {"co", "ac", "gov", "org", "com", "net", "ltd", "plc", "nhs", "sch"}

# Characters commonly substituted to fool the eye. Applied before comparing domains.
_CONFUSABLES = [("rn", "m"), ("vv", "w"), ("0", "o"), ("1", "l"), ("3", "e"), ("5", "s"),
                ("@", "a"), ("$", "s"), ("i", "l")]  # fmt: skip


def registrable_domain(host: str) -> str:
    """Approximate the domain someone actually registered: mail.paypal.com -> paypal.com.

    Handles common two-level suffixes such as .co.uk. (A full solution would use the
    Public Suffix List; this keeps the tool dependency-free.)
    """
    host = host.lower().strip(".")
    labels = host.split(".")
    if len(labels) >= 3 and labels[-2] in _SECOND_LEVEL and len(labels[-1]) == 2:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def host_of(url: str) -> str:
    if url.lower().startswith("www."):
        url = "http://" + url
    try:
        return (urlsplit(url).hostname or "").lower()
    except ValueError:
        return ""


# Cyrillic and Greek letters that are pixel-identical (or nearly) to Latin ones.
_HOMOGLYPHS = str.maketrans(
    {
        "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x", "і": "i",
        "ј": "j", "ѕ": "s", "ԁ": "d", "ɡ": "g", "һ": "h", "ӏ": "l", "ο": "o", "α": "a",
        "ν": "v", "τ": "t", "κ": "k", "ρ": "p",
    }
)  # fmt: skip


def decode_idn(host: str) -> str:
    """Show the real characters behind punycode: xn--pple-43d.com -> 'аpple.com' (Cyrillic а)."""
    labels = []
    for label in host.split("."):
        if label.startswith("xn--"):
            try:
                label = label.encode("ascii").decode("idna")
            except UnicodeError:
                pass
        labels.append(label)
    return ".".join(labels)


def skeleton(name: str) -> str:
    """Collapse visually confusable characters so 'paypa1' and 'paypal' compare equal."""
    name = name.lower().translate(_HOMOGLYPHS).replace("-", "")
    for fake, real in _CONFUSABLES:
        name = name.replace(fake, real)
    return name


def edit_distance(a: str, b: str) -> int:
    """Levenshtein distance: the number of single-character edits from a to b."""
    if len(a) < len(b):
        a, b = b, a
    previous = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        current = [i]
        for j, cb in enumerate(b, 1):
            current.append(min(previous[j] + 1, current[j - 1] + 1, previous[j - 1] + (ca != cb)))
        previous = current
    return previous[-1]


def lookalike_of(host: str, brands: tuple[str, ...] | list[str]) -> str | None:
    """Return the brand domain that ``host`` imitates, or None if it looks unrelated.

    A host that genuinely belongs to the brand (e.g. www.paypal.com) is not a look-alike.
    """
    if not host:
        return None
    reg = registrable_domain(host)
    for brand in brands:
        if reg == brand or host == brand or host.endswith("." + brand):
            return None  # really is the brand

    host = decode_idn(host)
    reg = registrable_domain(host)
    reg_name = reg.split(".")[0]
    suffix = reg.partition(".")[2]
    # Prefer brands with the same ending: amaz0n.co.uk imitates amazon.co.uk, not amazon.com.
    ordered = sorted(brands, key=lambda b: b.partition(".")[2] != suffix)
    for brand in ordered:
        brand_name = brand.split(".")[0]
        if len(brand_name) < 4:
            continue  # too short to compare meaningfully ("dhl")
        # 1) Brand domain used as a subdomain of something else.
        if f"{brand}." in host + "." and not host.endswith(brand):
            return brand
        # 2) Same name after undoing character swaps, or within a small typo.
        if skeleton(reg_name) == skeleton(brand_name) and reg_name != brand_name:
            return brand
        if reg_name != brand_name and edit_distance(reg_name, brand_name) <= (
            1 if len(brand_name) <= 6 else 2
        ):
            return brand
    return None


def is_punycode(host: str) -> bool:
    return any(label.startswith("xn--") for label in host.split("."))


def describe(host: str) -> str:
    """'xn--pple-43d.com' -> "'xn--pple-43d.com' (displayed as 'аpple.com')"; else quoted."""
    shown = decode_idn(host)
    return f"'{host}' (displayed as '{shown}')" if shown != host else f"'{host}'"


def brand_label(brand: str) -> str:
    """northwind-bank.example -> 'Northwind Bank'."""
    return brand.split(".")[0].replace("-", " ").title()
