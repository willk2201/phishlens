"""Command-line interface.

Exit codes: 0 = analysed, 1 = an email reached the ``--fail-on`` verdict, 2 = error.
"""

from __future__ import annotations

import argparse
import sys
from email.errors import MessageError
from pathlib import Path

from . import __version__
from .checks import REGISTRY, Context
from .domains import DEFAULT_BRANDS
from .engine import analyse_file
from .report import to_html, to_json, to_text

FAIL_LEVELS = {"suspicious": 25, "phishing": 55}


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="phishlens",
        description="Analyse suspicious emails (.eml files) and explain the warning signs.",
    )
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = p.add_subparsers(dest="command", required=True)

    a = sub.add_parser("analyse", aliases=["analyze"], help="analyse one or more .eml files")
    a.add_argument("files", nargs="+", type=Path, help=".eml files to analyse")
    a.add_argument(
        "--brands",
        type=Path,
        metavar="FILE",
        help="extra domains to protect from impersonation, one per line",
    )
    a.add_argument("--json", type=Path, metavar="PATH", help="write a JSON report")
    a.add_argument("--html", type=Path, metavar="PATH", help="write an HTML report")
    a.add_argument(
        "--fail-on",
        choices=list(FAIL_LEVELS),
        help="exit 1 if any email is at least this risky",
    )
    a.add_argument("--no-color", action="store_true")
    a.add_argument("-q", "--quiet", action="store_true", help="no terminal report")

    sub.add_parser("checks", help="list all checks")
    return p  # fmt: skip


def load_brands(path: Path | None) -> tuple[str, ...]:
    extra = []
    if path:
        for line in path.read_text(encoding="utf-8").splitlines():
            line = line.split("#", 1)[0].strip().lower()
            if line:
                extra.append(line)
    return tuple(dict.fromkeys([*DEFAULT_BRANDS, *extra]))


def cmd_analyse(args: argparse.Namespace) -> int:
    try:
        ctx = Context(brands=load_brands(args.brands))
    except OSError as exc:
        print(f"phishlens: error: cannot read brands file: {exc}", file=sys.stderr)
        return 2

    analyses = []
    for path in args.files:
        if not path.is_file():
            print(f"phishlens: error: no such file: {path}", file=sys.stderr)
            return 2
        try:
            analyses.append(analyse_file(path, ctx))
        except (OSError, MessageError) as exc:
            print(f"phishlens: error: could not read {path}: {exc}", file=sys.stderr)
            return 2

    if not args.quiet:
        color = not args.no_color and sys.stdout.isatty()
        print(("\n" + "─" * 72 + "\n").join(to_text(a, color) for a in analyses))
    if args.json:
        args.json.write_text(to_json(analyses), encoding="utf-8")
        print(f"JSON report written to {args.json}", file=sys.stderr)
    if args.html:
        args.html.write_text(to_html(analyses), encoding="utf-8")
        print(f"HTML report written to {args.html}", file=sys.stderr)

    if args.fail_on and any(a.score >= FAIL_LEVELS[args.fail_on] for a in analyses):
        return 1
    return 0


def cmd_checks() -> int:
    for c in REGISTRY:
        print(f"{c.id}  [{c.category:<14}] {c.title}")
    return 0


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "checks":
        return cmd_checks()
    return cmd_analyse(args)
