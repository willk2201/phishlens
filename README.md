# PhishLens

[![CI](https://github.com/willk2201/phishlens/actions/workflows/ci.yml/badge.svg)](https://github.com/willk2201/phishlens/actions/workflows/ci.yml)
![Python](https://img.shields.io/badge/python-3.10%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)

PhishLens is a command-line tool that looks at a suspicious email (a `.eml` file) and points
out the signs that it might be phishing, with a short explanation of why each one matters.

I made it because phishing is still one of the most common ways attacks start, and I wanted
to understand how you can actually tell a fake email apart from a real one, beyond just
"check the spelling". It's a learning project, not a replacement for a proper email filter.

## Example

```text
$ phishlens analyse samples/02_account_suspended.eml --brands samples/brands.txt

  From:    Northwind Bank Security <security@n0rthwind-bank.example>
  Subject: URGENT: Your account has been suspended

 LIKELY PHISHING   risk score 100/100

 HIGH    DMARC fail
         The visible From address (n0rthwind-bank.example) is not backed by a passing SPF
         or DKIM check. This is the strongest sign the sender is being impersonated.

 HIGH    Link text hides a different destination
         The link says 'www.northwind-bank.example' but actually goes to '203.0.113.50'.

 HIGH    Sender domain imitates northwind-bank.example
 HIGH    Replies go to a different domain
 MEDIUM  Asks for passwords or personal details
 ...
```

There's also an [HTML report](docs/sample-report.html) for all five sample emails.

## What it checks

| ID     | Check                        | Example of what it catches                               |
|--------|------------------------------|----------------------------------------------------------|
| PL-A01 | SPF / DKIM / DMARC results   | The email failed sender authentication                   |
| PL-S01 | Look-alike sender domain     | `paypa1.com`, `rnicrosoft.com`, Unicode look-alikes      |
| PL-S02 | Display name tricks          | "PayPal Support" sent from a random domain               |
| PL-S03 | Reply-To redirection         | Replies secretly go to a different address               |
| PL-L01 | Link text vs real link       | Text shows the bank's site, link goes to an IP address   |
| PL-L02 | Suspicious links             | Look-alike domains, raw IPs, `@` tricks, URL shorteners  |
| PL-C01 | Pressure language            | Urgency, password requests, gift cards, secrecy          |
| PL-F01 | Risky attachments            | `invoice.pdf.exe`, scripts, macro files, HTML files      |

Each finding adds to a risk score out of 100. Under 25 is "Likely safe", 25 to 54 is
"Suspicious", and 55 or more is "Likely phishing".

## Running it

You need Python 3.10 or newer. There are no other dependencies.

```bash
git clone https://github.com/willk2201/phishlens.git
cd phishlens
python -m venv .venv
.venv\Scripts\activate          # on Mac/Linux: source .venv/bin/activate
pip install -e ".[dev]"

phishlens analyse samples/*.eml --brands samples/brands.txt --html report.html
```

To check a real email, save it as a `.eml` file first (in Gmail it's ⋮ then
"Download message"), then run `phishlens analyse your-email.eml`.

The `--brands` option takes a text file of extra domains to watch for impersonation, one per
line. `phishlens checks` lists all the checks.

## Sample emails

The `samples` folder has five test emails. Everything in them is made up: the domains end in
`.example`, which is reserved and can never be a real website, and the IP addresses are from
ranges set aside for documentation. The attachments are just placeholder text with
suspicious file names.

| File                           | What it is                               | Result          |
|--------------------------------|------------------------------------------|-----------------|
| `01_legitimate_newsletter.eml` | A normal email, to compare against       | Likely safe     |
| `02_account_suspended.eml`     | Fake "account suspended" login phish     | Likely phishing |
| `03_invoice_attachment.eml`    | Fake invoice with a disguised `.exe`     | Likely phishing |
| `04_ceo_gift_cards.eml`        | "CEO" asking for gift cards              | Likely phishing |
| `05_homograph_link.eml`        | Domain using a Cyrillic "о"              | Likely phishing |

Sample 04 is my favourite one. It actually **passes** SPF, DKIM and DMARC, because it was
genuinely sent from a free email account. That shows the authentication checks only prove
which server sent an email, not that the person is who they say they are. The tool still
catches it from the "CEO" name on a free email address, the gift card request and the
"keep this between us".

You can regenerate the samples with `python scripts/generate_samples.py`.

## How it works

```text
src/phishlens/
├── parse.py          # reads the .eml file: sender, links, attachments
├── domains.py        # look-alike domain detection
├── checks/           # one file per type of check
├── engine.py         # runs all the checks
├── report.py         # terminal, JSON and HTML output
└── cli.py            # command-line interface
```

A few things I thought were interesting while working on it:

- **Look-alike domains.** To decide if a domain is pretending to be a brand, it compares
  them in three ways: after swapping back common character tricks (`0` for `o`, `rn` for
  `m`), by counting how many letters are different (Levenshtein distance), and by checking
  if the real brand name is being used as a subdomain, like `paypal.com.account-check.example`.
- **Unicode tricks.** Domains with non-English letters are stored in "punycode", e.g.
  `xn--80ak6aa92e.com`. Decoded, that's "аррӏе.com", written entirely in Cyrillic letters,
  but it looks just like apple.com. The tool decodes these and shows what the person would
  actually have seen.
- **Which headers to trust.** Each mail server adds its headers at the top, so an attacker
  can add a fake "dmarc=pass" line further down. Only the top `Authentication-Results`
  header, added by your own mail server, is used.
- **Wording counts for less.** Real companies send urgent emails too, so pressure language
  on its own only gives a low score. Things like a forged sender or a link that lies about
  where it goes count for a lot more.

## Safety

- Links in the reports are "defanged" (`hxxps://evil[.]example`) so nobody can click them
  by accident if a report gets shared.
- Emails are treated as untrusted. The HTML report escapes everything from the email so
  nothing in it can run as code.
- Attachments are never opened, only their names are checked.
- `.gitignore` blocks `.eml` files outside `samples/` so real emails don't get committed
  by mistake.

## Limitations

- It's based on rules of thumb, so a well-written phishing email from a normal-looking domain
  with no links could get a low score.
- Look-alike detection only knows about the brands in its list.
- It doesn't check links against any blocklist, and it never visits them.
- The language checks only work for English.

## Ideas for later

- Check domains against a blocklist
- Detect QR codes in images, which some phishing emails now use instead of links
- Show the route the email took using the `Received` headers

## Tests

```bash
pytest
ruff check .
```

There are 93 tests, covering the checks, the email parsing and the sample emails.

## Other projects

- [LogSentry](https://github.com/willk2201/logsentry): finds attacks in server logs
- [HardenCheck](https://github.com/willk2201/hardencheck): checks a website's security headers and TLS

## License

MIT
